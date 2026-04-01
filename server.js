// =====================================================
// PanelFlow DIY - 웹훅 서버
// Node.js (Express) - Render.com 무료 플랜 배포용
//
// 파일 구조:
// /
// ├── server.js (이 파일)
// ├── package.json
// └── .env (로컬 테스트용)
// =====================================================

const express = require("express");
const crypto = require("crypto");
const Mixpanel = require("mixpanel");

const app = express();
app.use(express.json());

// ============================================================
// 환경변수 설정 (Render 환경변수에 등록)
// ============================================================
const CAFE24_CLIENT_SECRET = process.env.CAFE24_CLIENT_SECRET; // 카페24 웹훅 시크릿
const MIXPANEL_TOKEN = process.env.MIXPANEL_TOKEN; // 믹스패널 토큰
const PORT = process.env.PORT || 3000;

const mp = Mixpanel.init(MIXPANEL_TOKEN, { protocol: "https" });

// ============================================================
// 카페24 웹훅 서명 검증
// X-Cafe24-Signature 헤더로 검증
// ============================================================
function verifyCafe24Signature(req) {
  const signature = req.headers["x-cafe24-signature"];
  if (!signature) return false;

  const body = JSON.stringify(req.body);
  const hmac = crypto
    .createHmac("sha256", CAFE24_CLIENT_SECRET)
    .update(body)
    .digest("base64");

  return hmac === signature;
}

// ============================================================
// 공통 서버 이벤트 프로퍼티 생성
// ============================================================
function buildServerCommon(data) {
  return {
    mall_id: data.mall_id || "",
    shop_no: data.shop_no || 1,
    order_id: (data.order && data.order.order_id) || "",
    buyer_member_id: (data.order && data.order.buyer_member_id) || "",
    buyer_is_guest: data.order && !data.order.buyer_member_id ? true : false,
    $insert_id: `${data.event_no || ""}_${(data.order && data.order.order_id) || Date.now()}`,
  };
}

// ============================================================
// items_detail 파싱
// [임의결정] 카페24 웹훅 order.items 배열 기준
// 실제 웹훅 페이로드 구조는 카페24 개발자센터 확인 필요
// ============================================================
function parseItems(items, eventType) {
  if (!items || !Array.isArray(items)) return [];
  return items.map(function (item) {
    var parsed = {
      item_order_item_code: item.order_item_code || "",
      item_product_no: item.product_no || 0,
      item_product_name: item.product_name || "",
      // [임의결정] 옵션 문자열 그대로 사용
      item_variant_info: item.variant_code || item.option_value || "",
      item_quantity: item.quantity || 1,
      item_price_original: item.product_price || 0,
      item_payment_amount_final:
        item.actual_payment_amount || item.product_price || 0,
    };
    if (eventType === "cancel") {
      parsed.item_cancellation_fee = item.cancel_fee || 0;
    }
    return parsed;
  });
}

// ============================================================
// Complete Order 웹훅
// 카페24 웹훅 이벤트: order_paid (결제 완료)
// ============================================================
app.post("/webhook/order-paid", function (req, res) {
  if (!verifyCafe24Signature(req)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const data = req.body;
  const order = data.order || {};
  const common = buildServerCommon(data);

  const distinctId = order.buyer_member_id || `guest_${order.order_id}`;

  const props = Object.assign(common, {
    // order_detail
    order_detail: {
      order_price_amount: order.order_price_amount || 0,
      shipping_fee_amount: order.shipping_fee || 0,
      points_spent_amount: order.points_used || 0,
      credits_spent_amount: order.credits_used || 0,
      coupon_discount_amount: order.coupon_discount || 0,
      membership_discount_amount: order.member_discount || 0,
      benefit_amount: order.benefit_amount || 0,
      payment_amount: order.payment_amount || 0,
    },
    // shipping_info
    shipping_info: {
      receiver_name: order.receiver_name || "",
      receiver_phone: order.receiver_phone || "",
      zip_code: order.shipping_zipcode || "",
      address_full:
        (order.shipping_address1 || "") + " " + (order.shipping_address2 || ""),
      message: order.shipping_message || "",
      type_text: order.delivery_type || "",
      status_code: order.shipping_status || "",
    },
    items_detail: parseItems(order.items, "complete"),
  });

  mp.track("Complete Order", props, { distinct_id: distinctId });

  console.log("[PF] Complete Order tracked:", order.order_id);
  res.json({ success: true });
});

// ============================================================
// Cancel Order 웹훅
// 카페24 웹훅 이벤트: order_cancelled
// ============================================================
app.post("/webhook/order-cancelled", function (req, res) {
  if (!verifyCafe24Signature(req)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const data = req.body;
  const order = data.order || {};
  const common = buildServerCommon(data);

  const distinctId = order.buyer_member_id || `guest_${order.order_id}`;

  const props = Object.assign(common, {
    items_detail: parseItems(order.items, "cancel"),
    cancellation_detail: {
      claim_code: order.claim_code || "",
      reason: order.cancel_reason || "",
      payment_amount: order.refund_amount || 0,
      payment_method: order.refund_methods || [],
    },
  });

  mp.track("Cancel Order Item", props, { distinct_id: distinctId });

  console.log("[PF] Cancel Order tracked:", order.order_id);
  res.json({ success: true });
});

// ============================================================
// 헬스체크 (Render 무료 플랜 슬립 방지용)
// ============================================================
app.get("/health", function (req, res) {
  res.json({ status: "ok", time: new Date().toISOString() });
});

app.listen(PORT, function () {
  console.log(`[PF] Webhook server running on port ${PORT}`);
});
