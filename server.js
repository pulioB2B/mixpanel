// =====================================================
// PanelFlow DIY - 웹훅 서버
// Node.js (Express) - Render.com 무료 플랜 배포용
// =====================================================

const express = require("express");
const crypto = require("crypto");
const Mixpanel = require("mixpanel");

const app = express();

// 웹훅 서명 검증을 위해 raw body 필요 → json 파싱 전에 저장
app.use(
  express.json({
    verify: function (req, res, buf) {
      req.rawBody = buf.toString("utf8");
    },
  }),
);

// ============================================================
// 환경변수
// CAFE24_CLIENT_SECRET : 카페24 앱의 Client Secret
// MIXPANEL_TOKEN       : 운영 믹스패널 프로젝트 토큰
// ============================================================
const CAFE24_CLIENT_SECRET = process.env.CAFE24_CLIENT_SECRET;
const MIXPANEL_TOKEN = process.env.MIXPANEL_TOKEN;
const PORT = process.env.PORT || 3000;

const mp = Mixpanel.init(MIXPANEL_TOKEN, { protocol: "https" });

// ============================================================
// 카페24 웹훅 서명 검증
// X-Cafe24-Signature 헤더 = HMAC-SHA256(rawBody, clientSecret) → Base64
// ============================================================
function verifyCafe24Signature(req) {
  if (!CAFE24_CLIENT_SECRET) return true; // 로컬 테스트 시 검증 스킵
  const signature = req.headers["x-cafe24-signature"];
  if (!signature) return false;
  const hmac = crypto
    .createHmac("sha256", CAFE24_CLIENT_SECRET)
    .update(req.rawBody)
    .digest("base64");
  return hmac === signature;
}

// ============================================================
// 샘플 데이터 기반 확인된 페이로드 구조:
// {
//   event_no: 90023,
//   resource: {
//     mall_id, event_shop_no, event_code,
//     order_id, payment_gateway_name, currency,
//     order_date, order_place_name,
//     member_id,                        ← distinct_id
//     buyer_name, buyer_email,
//     buyer_phone, buyer_cellphone,
//     paid,                             ← "T"/"F"
//     payment_date,
//     payment_method,                   ← "card","mileage" 등
//     order_price_amount,               ← 상품 총액
//     actual_payment_amount,            ← 실제 결제금액
//     mileage_spent_amount,             ← 적립금 사용
//     membership_discount_amount,       ← 등급 할인
//     shipping_fee,
//     ordering_product_code,            ← 쉼표 구분 문자열
//     ordering_product_name,            ← 쉼표 구분 문자열
//     ...
//   }
// }
// ============================================================

app.get("/", function (req, res) {
  const code = req.query.code;
  const mallId = req.query.mall_id;

  if (code) {
    // [중요] 여기서 원래는 code를 가지고 Access Token을 발급받아야 설치가 완료됩니다.
    // 하지만 단순 웹훅용이라면, 일단 카페24가 요청을 보냈을 때 화면을 보여주는 것만으로도
    // 브라우저상에서 설치 프로세스가 진행될 수 있습니다.
    console.log(`[PF] 설치 요청 수신: 쇼핑몰=${mallId}, 코드=${code}`);
    res.send(`<h1>앱 설치가 진행 중입니다.</h1><p>쇼핑몰: ${mallId}</p>`);
  } else {
    res.send("PanelFlow 웹훅 서버가 작동 중입니다.");
  }
});

// ============================================================
// Complete Order 웹훅
// 이벤트 코드: create_order (주문 생성 + paid: "T" 확인)
// ============================================================
app.post("/webhook/order", function (req, res) {
  if (!verifyCafe24Signature(req)) {
    console.warn("[PF] 서명 검증 실패");
    return res.status(401).json({ error: "Invalid signature" });
  }

  const data = req.body;
  const resource = data.resource || {};
  const eventCode = resource.event_code || "";

  console.log("[PF] 웹훅 수신:", eventCode, resource.order_id);

  // create_order: 주문 생성
  if (eventCode === "create_order") {
    handleCompleteOrder(data, res);
    return;
  }

  // cancel_order: 주문 취소
  if (eventCode === "cancel_order") {
    handleCancelOrder(data, res);
    return;
  }

  // 그 외 이벤트는 200 응답만
  res.json({ success: true, skipped: eventCode });
});

// ============================================================
// Complete Order 처리
// ============================================================
function handleCompleteOrder(data, res) {
  const r = data.resource || {};

  // 비회원이면 order_id 기반 임시 ID 사용
  const distinctId = r.member_id ? r.member_id : "guest_" + r.order_id;

  // 상품 목록 파싱 (쉼표 구분 문자열)
  const productCodes = r.ordering_product_code
    ? r.ordering_product_code.split(",").map(function (s) {
        return s.trim();
      })
    : [];
  const productNames = r.ordering_product_name
    ? r.ordering_product_name.split(",").map(function (s) {
        return s.trim();
      })
    : [];

  const items = productCodes.map(function (code, i) {
    return {
      item_product_code: code,
      item_product_name: productNames[i] || "",
    };
  });

  const props = {
    // 공통 서버 프로퍼티
    mall_id: r.mall_id || "",
    shop_no: r.event_shop_no || 1,
    order_id: r.order_id || "",
    buyer_member_id: r.member_id || "",
    buyer_is_guest: !r.member_id,
    // 중복 방지 키
    $insert_id: "complete_order_" + r.order_id,

    // 주문 상세
    order_date: r.order_date || "",
    payment_date: r.payment_date || "",
    payment_method: r.payment_method || "",
    payment_gateway: r.payment_gateway_name || "",
    order_place: r.order_place_name || "",
    order_place_id: r.order_place_id || "",
    currency: r.currency || "KRW",
    is_paid: r.paid === "T",
    order_from_mobile: r.order_from_mobile === "T",

    // 금액 (문자열 → 숫자 변환)
    order_price_amount: parseFloat(r.order_price_amount) || 0,
    actual_payment_amount: parseFloat(r.actual_payment_amount) || 0,
    mileage_spent_amount: parseFloat(r.mileage_spent_amount) || 0,
    membership_discount_amount: parseFloat(r.membership_discount_amount) || 0,
    shipping_fee: parseFloat(r.shipping_fee) || 0,

    // 배송
    shipping_type: r.shipping_type || "",
    shipping_status: r.shipping_status || "",
    shipping_message: r.shipping_message || "",

    // 구매자
    buyer_name: r.buyer_name || "",
    buyer_email: r.buyer_email || "",
    buyer_cellphone: r.buyer_cellphone || "",

    // 상품 목록
    items_detail: items,
  };

  mp.track("Complete Order", props, { distinct_id: distinctId });
  console.log(
    "[PF] Complete Order tracked:",
    r.order_id,
    "/ distinct_id:",
    distinctId,
  );
  res.json({ success: true });
}

// ============================================================
// Cancel Order 처리
// 카페24 cancel_order 웹훅 페이로드는 create_order와 유사
// 실제 수신 후 resource 필드 콘솔 로그로 확인 권장
// ============================================================
function handleCancelOrder(data, res) {
  const r = data.resource || {};

  const distinctId = r.member_id ? r.member_id : "guest_" + r.order_id;

  const props = {
    mall_id: r.mall_id || "",
    shop_no: r.event_shop_no || 1,
    order_id: r.order_id || "",
    buyer_member_id: r.member_id || "",
    buyer_is_guest: !r.member_id,
    $insert_id: "cancel_order_" + r.order_id,

    cancel_date: r.cancel_date || r.order_date || "",
    payment_method: r.payment_method || "",

    order_price_amount: parseFloat(r.order_price_amount) || 0,
    actual_payment_amount: parseFloat(r.actual_payment_amount) || 0,
    refund_amount: parseFloat(r.refund_amount) || 0,
    cancel_reason: r.cancel_reason || "",

    buyer_name: r.buyer_name || "",
    buyer_cellphone: r.buyer_cellphone || "",
  };

  mp.track("Cancel Order Item", props, { distinct_id: distinctId });
  console.log("[PF] Cancel Order tracked:", r.order_id);
  res.json({ success: true });
}

// ============================================================
// 헬스체크 (Render 무료 슬립 방지)
// ============================================================
app.get("/health", function (req, res) {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// 웹훅 페이로드 디버그용 (개발 시에만 사용, 운영 시 제거)
app.post("/webhook/debug", function (req, res) {
  console.log("[DEBUG] Headers:", JSON.stringify(req.headers, null, 2));
  console.log("[DEBUG] Body:", JSON.stringify(req.body, null, 2));
  res.json({ received: true });
});

app.listen(PORT, function () {
  console.log("[PF] Webhook server running on port " + PORT);
});
