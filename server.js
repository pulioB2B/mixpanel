// =====================================================
// PanelFlow DIY - 웹훅 서버 (OAuth 설치 + 웹훅 처리 통합)
// Node.js (Express) - Render.com 무료 플랜 배포용
// =====================================================

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

// ============================================================
// 환경변수 (Render 대시보드에서 등록)
// ============================================================
const CLIENT_ID = process.env.CAFE24_CLIENT_ID;
const CLIENT_SECRET = process.env.CAFE24_CLIENT_SECRET;
const MALL_ID = process.env.CAFE24_MALL_ID; // "pulio365"
const MIXPANEL_TOKEN = process.env.MIXPANEL_TOKEN;
const PORT = process.env.PORT || 3000;

// Redirect URI = 이 서버의 /oauth/callback 경로
// Render 배포 후 실제 URL로 설정 (예: https://pf-webhook.onrender.com/oauth/callback)
const REDIRECT_URI = process.env.REDIRECT_URI;

const mp = Mixpanel.init(MIXPANEL_TOKEN, { protocol: "https" });

// ============================================================
// OAuth STEP 1: 카페24가 설치 시작할 때 이 서버 루트("/")로 리다이렉트
// 카페24 → GET / → 서버가 카페24 인증 페이지로 다시 리다이렉트
// ============================================================
app.get("/", function (req, res) {
  const mallId = req.query.mall_id || MALL_ID;

  // 이미 code가 넘어온 경우 (일부 카페24 버전)
  if (req.query.code) {
    return handleOAuthCallback(req, res);
  }

  // 카페24 인증 페이지로 리다이렉트
  const authUrl =
    `https://${mallId}.cafe24api.com/api/v2/oauth/authorize?` +
    `response_type=code&` +
    `client_id=${CLIENT_ID}&` +
    `state=pf_install&` +
    `redirect_uri=${encodeURIComponent(REDIRECT_URI)}&` +
    `scope=mall.read_order,mall.read_customer`;

  console.log("[PF] 앱 설치 시작, 인증 페이지로 리다이렉트:", mallId);
  res.redirect(authUrl);
});

// ============================================================
// OAuth STEP 2: 인증 완료 후 카페24가 code를 이 경로로 보냄
// ============================================================
app.get("/oauth/callback", function (req, res) {
  handleOAuthCallback(req, res);
});

async function handleOAuthCallback(req, res) {
  const { code, error, error_description, mall_id } = req.query;
  const mallId = mall_id || MALL_ID;

  if (error) {
    console.error("[PF] OAuth 에러:", error, error_description);
    return res.status(400).send(`설치 오류: ${error_description}`);
  }

  if (!code) {
    return res.status(400).send("인증 코드가 없습니다.");
  }

  try {
    // Access Token 발급
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
    console.log("[PF] Refresh Token:", tokenData.refresh_token);

    // 토큰 저장 필요 시 여기서 DB/파일에 저장
    // 지금은 웹훅만 쓸 것이므로 로그만 남기고 성공 응답

    res.send(`
            <html>
            <body style="font-family:sans-serif; text-align:center; padding:50px;">
                <h1>✅ 앱 설치 완료!</h1>
                <p>PanelFlow 웹훅이 쇼핑몰 <strong>${mallId}</strong>에 연결되었습니다.</p>
                <p>이 창을 닫으셔도 됩니다.</p>
            </body>
            </html>
        `);
  } catch (err) {
    const errData = err.response ? err.response.data : err.message;
    console.error("[PF] 토큰 발급 실패:", JSON.stringify(errData));
    res.status(500).send(`
            <html>
            <body style="font-family:sans-serif; text-align:center; padding:50px;">
                <h1>❌ 설치 실패</h1>
                <p>${JSON.stringify(errData)}</p>
            </body>
            </html>
        `);
  }
}

// ============================================================
// 웹훅 서명 검증
// ============================================================
function verifyCafe24Signature(req) {
  if (!CLIENT_SECRET) return true;
  const signature = req.headers["x-cafe24-signature"];
  if (!signature) return false;
  const hmac = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(req.rawBody)
    .digest("base64");
  return hmac === signature;
}

// ============================================================
// 웹훅 수신 엔드포인트
// create_order / cancel_order 통합 처리
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

// ============================================================
// Complete Order
// ============================================================
function handleCompleteOrder(data, res) {
  const r = data.resource || {};
  const distinctId = r.member_id ? r.member_id : "guest_" + r.order_id;

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
    mall_id: r.mall_id || "",
    shop_no: r.event_shop_no || 1,
    order_id: r.order_id || "",
    buyer_member_id: r.member_id || "",
    buyer_is_guest: !r.member_id,
    $insert_id: "complete_order_" + r.order_id,
    order_date: r.order_date || "",
    payment_date: r.payment_date || "",
    payment_method: r.payment_method || "",
    payment_gateway: r.payment_gateway_name || "",
    order_place: r.order_place_name || "",
    order_place_id: r.order_place_id || "",
    currency: r.currency || "KRW",
    is_paid: r.paid === "T",
    order_from_mobile: r.order_from_mobile === "T",
    order_price_amount: parseFloat(r.order_price_amount) || 0,
    actual_payment_amount: parseFloat(r.actual_payment_amount) || 0,
    mileage_spent_amount: parseFloat(r.mileage_spent_amount) || 0,
    membership_discount_amount: parseFloat(r.membership_discount_amount) || 0,
    shipping_fee: parseFloat(r.shipping_fee) || 0,
    shipping_type: r.shipping_type || "",
    shipping_status: r.shipping_status || "",
    shipping_message: r.shipping_message || "",
    buyer_name: r.buyer_name || "",
    buyer_email: r.buyer_email || "",
    buyer_cellphone: r.buyer_cellphone || "",
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
// Cancel Order
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
// 헬스체크
// ============================================================
app.get("/health", function (req, res) {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// 디버그용 (운영 시 제거)
app.post("/webhook/debug", function (req, res) {
  console.log("[DEBUG] Headers:", JSON.stringify(req.headers, null, 2));
  console.log("[DEBUG] Body:", JSON.stringify(req.body, null, 2));
  res.json({ received: true });
});

app.listen(PORT, function () {
  console.log("[PF] 서버 실행 중, 포트:", PORT);
});
