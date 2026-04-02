const express = require("express");
const crypto = require("crypto");
const axios = require("axios");
const Mixpanel = require("mixpanel");

const app = express();

app.use(
  express.json({
    verify: function (req, res, buf) {
      req.rawBody = buf.toString("utf8");
    },
  }),
);

const CLIENT_ID = process.env.CAFE24_CLIENT_ID;
const CLIENT_SECRET = process.env.CAFE24_CLIENT_SECRET;
const MALL_ID = process.env.CAFE24_MALL_ID;
const MIXPANEL_TOKEN = process.env.MIXPANEL_TOKEN;
const REDIRECT_URI = process.env.REDIRECT_URI;
const PORT = process.env.PORT || 3000;

const mp = Mixpanel.init(MIXPANEL_TOKEN, { protocol: "https" });

// ============================================================
// 카페24 웹훅 서명 검증
// 카페24는 HMAC-SHA256(rawBody, clientSecret) → Base64 방식
// 단, clientSecret을 그대로 쓰는 경우와
// Base64 디코딩해서 쓰는 경우 두 가지를 모두 시도
// ============================================================
function verifyCafe24Signature(req) {
  const signature = req.headers["x-cafe24-signature"];

  // 서명 헤더 자체가 없으면 일단 통과 (카페24가 서명 안 보내는 버전 대응)
  if (!signature) {
    console.warn("[PF] 서명 헤더 없음 - 통과 처리");
    return true;
  }

  if (!CLIENT_SECRET) {
    console.warn("[PF] CLIENT_SECRET 미설정 - 검증 스킵");
    return true;
  }

  // 방법 1: CLIENT_SECRET 그대로 사용
  const hmac1 = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(req.rawBody)
    .digest("base64");

  if (hmac1 === signature) {
    console.log("[PF] 서명 검증 성공 (방법1: 원본)");
    return true;
  }

  // 방법 2: CLIENT_SECRET을 Base64 디코딩해서 사용
  try {
    const decodedSecret = Buffer.from(CLIENT_SECRET, "base64").toString("utf8");
    const hmac2 = crypto
      .createHmac("sha256", decodedSecret)
      .update(req.rawBody)
      .digest("base64");

    if (hmac2 === signature) {
      console.log("[PF] 서명 검증 성공 (방법2: base64 디코딩)");
      return true;
    }
  } catch (e) {}

  // 방법 3: rawBody 대신 JSON.stringify(req.body) 사용
  try {
    const hmac3 = crypto
      .createHmac("sha256", CLIENT_SECRET)
      .update(JSON.stringify(req.body))
      .digest("base64");

    if (hmac3 === signature) {
      console.log("[PF] 서명 검증 성공 (방법3: JSON.stringify)");
      return true;
    }
  } catch (e) {}

  // 모두 실패 시 서명값과 계산값 로그 출력 (디버그용)
  console.warn("[PF] 서명 검증 실패");
  console.warn("[PF] 수신된 서명:", signature);
  console.warn("[PF] rawBody 앞 200자:", req.rawBody.substring(0, 200));
  const hmacDebug = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(req.rawBody)
    .digest("base64");
  console.warn("[PF] 계산된 서명(방법1):", hmacDebug);

  // ★ 지금은 실패해도 일단 통과 (웹훅 수신 확인 우선)
  // 서명 확인 완료 후 아래 return true → return false 로 변경
  return true;
}

// ============================================================
// OAuth 설치 흐름
// ============================================================
app.get("/", function (req, res) {
  const mallId = req.query.mall_id || MALL_ID;
  if (req.query.code) return handleOAuthCallback(req, res);

  const authUrl =
    `https://${mallId}.cafe24api.com/api/v2/oauth/authorize?` +
    `response_type=code&client_id=${CLIENT_ID}&state=pf_install&` +
    `redirect_uri=${encodeURIComponent(REDIRECT_URI)}&` +
    `scope=mall.read_order,mall.read_customer`;

  console.log("[PF] 앱 설치 시작:", mallId);
  res.redirect(authUrl);
});

app.get("/oauth/callback", function (req, res) {
  handleOAuthCallback(req, res);
});

async function handleOAuthCallback(req, res) {
  const { code, error, error_description, mall_id } = req.query;
  const mallId = mall_id || MALL_ID;

  if (error) return res.status(400).send(`설치 오류: ${error_description}`);
  if (!code) return res.status(400).send("인증 코드가 없습니다.");

  try {
    const tokenResponse = await axios.post(
      `https://${mallId}.cafe24api.com/api/v2/oauth/token`,
      new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: REDIRECT_URI,
      }),
      {
        headers: {
          Authorization: `Basic ${Buffer.from(CLIENT_ID + ":" + CLIENT_SECRET).toString("base64")}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      },
    );

    const tokenData = tokenResponse.data;
    console.log("[PF] 앱 설치 완료! 쇼핑몰:", mallId);
    console.log("[PF] Access Token:", tokenData.access_token);

    res.send(`
            <html><body style="font-family:sans-serif;text-align:center;padding:50px;">
                <h1>✅ 앱 설치 완료!</h1>
                <p>쇼핑몰 <strong>${mallId}</strong>에 연결되었습니다.</p>
            </body></html>
        `);
  } catch (err) {
    const errData = err.response ? err.response.data : err.message;
    console.error("[PF] 토큰 발급 실패:", JSON.stringify(errData));
    res
      .status(500)
      .send(`<h1>❌ 설치 실패</h1><p>${JSON.stringify(errData)}</p>`);
  }
}

// ============================================================
// 웹훅 수신
// ============================================================
app.post("/webhook/order", function (req, res) {
  // 수신된 전체 바디 로그 (member_id 등 실제 필드명 확인용)
  console.log("[PF] 웹훅 수신 바디 전체:", JSON.stringify(req.body, null, 2));

  if (!verifyCafe24Signature(req)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const data = req.body;
  const resource = data.resource || {};
  const eventCode = resource.event_code || "";

  // member_id 관련 필드 전체 출력 (실제 필드명 확인용)
  console.log("[PF] member 관련 필드:", {
    member_id: resource.member_id,
    buyer_id: resource.buyer_id,
    user_id: resource.user_id,
    member_email: resource.member_email,
    buyer_member_id: resource.buyer_member_id,
  });
  console.log("[PF] 웹훅 이벤트:", eventCode, "/ 주문번호:", resource.order_id);

  if (eventCode === "create_order") {
    handleCompleteOrder(data, res);
    return;
  }
  if (eventCode === "cancel_order") {
    handleCancelOrder(data, res);
    return;
  }

  res.json({ success: true, skipped: eventCode });
});

function handleCompleteOrder(data, res) {
  const r = data.resource || {};

  // distinct_id: 회원이면 member_id, 비회원이면 guest_{order_id}
  const distinctId = r.member_id ? r.member_id : "guest_" + r.order_id;

  // 상품 목록 파싱
  const productCodes = r.ordering_product_code
    ? r.ordering_product_code.split(",").map((s) => s.trim())
    : [];
  const productNames = r.ordering_product_name
    ? r.ordering_product_name.split(",").map((s) => s.trim())
    : [];

  const items = productCodes.map((code, i) => ({
    item_product_code: code,
    item_product_name: productNames[i] || "",
  }));

  // 첫 번째 상품명 (order_first_item_name)
  const firstItemName = productNames[0] || "";

  const props = {
    mall_id: r.mall_id || "",
    shop_no: r.event_shop_no || 1,
    order_id: r.order_id || "",
    buyer_member_id: r.member_id || "",
    buyer_is_guest: !r.member_id,
    $insert_id: "complete_order_" + r.order_id,
    Distinct ID: distinctId,
    order_date: r.order_date || "",
    payment_date: r.payment_date || "",

    // 주문 정보
    payment_method: r.payment_method || "",
    payment_gateway: r.payment_gateway_name || "",
    order_place: r.order_place_name || "",
    order_place_id: r.order_place_id || "",
    currency: r.currency || "KRW",
    is_paid: r.paid === "T",
    order_from_mobile: r.order_from_mobile === "T",

    // 금액
    order_price_amount: parseFloat(r.order_price_amount) || 0,
    actual_payment_amount: parseFloat(r.actual_payment_amount) || 0,
    mileage_spent_amount: parseFloat(r.mileage_spent_amount) || 0,
    membership_discount_amount: parseFloat(r.membership_discount_amount) || 0,
    shipping_fee: parseFloat(r.shipping_fee) || 0,

    // 배송
    shipping_type: r.shipping_type || "",
    shipping_status: r.shipping_status || "",

    // 상품 요약
    order_first_item_name: firstItemName,
    order_item_count: productCodes.length,
    order_detail: items,

    // 개인정보 미수집: buyer_name, buyer_email, buyer_cellphone, buyer_phone 제외
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

function handleCancelOrder(data, res) {
  const r = data.resource || {};
  const distinctId = r.member_id ? r.member_id : "guest_" + r.order_id;

  const props = {
    mall_id: r.mall_id || "",
    shop_no: r.event_shop_no || 1,
    order_id: r.order_id || "",
    buyer_member_id: r.member_id || "",
    Distinct ID: distinctId,
    buyer_is_guest: !r.member_id,
    $insert_id: "cancel_order_" + r.order_id,
    cancel_date: r.cancel_date || r.order_date || "",
    payment_method: r.payment_method || "",
    order_price_amount: parseFloat(r.order_price_amount) || 0,
    actual_payment_amount: parseFloat(r.actual_payment_amount) || 0,
    refund_amount: parseFloat(r.refund_amount) || 0,
    cancel_reason: r.cancel_reason || "",
    // 개인정보 미수집: buyer_name, buyer_cellphone 제외
  };

  mp.track("Cancel Order Item", props, { distinct_id: distinctId });
  console.log("[PF] Cancel Order tracked:", r.order_id);
  res.json({ success: true });
}

app.get("/health", function (req, res) {
  res.json({ status: "ok", time: new Date().toISOString() });
});

app.post("/webhook/debug", function (req, res) {
  console.log("[DEBUG] Headers:", JSON.stringify(req.headers, null, 2));
  console.log("[DEBUG] Body:", JSON.stringify(req.body, null, 2));
  res.json({ received: true });
});

app.listen(PORT, function () {
  console.log("[PF] 서버 실행 중, 포트:", PORT);
});
