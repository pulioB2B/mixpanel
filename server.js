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
// 서명 검증
// ============================================================
function verifyCafe24Signature(req) {
  const signature = req.headers["x-cafe24-signature"];
  if (!signature) {
    console.warn("[PF] 서명 헤더 없음 - 통과");
    return true;
  }
  if (!CLIENT_SECRET) {
    console.warn("[PF] CLIENT_SECRET 미설정 - 스킵");
    return true;
  }

  const hmac1 = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(req.rawBody)
    .digest("base64");
  if (hmac1 === signature) {
    console.log("[PF] 서명 검증 성공 (방법1)");
    return true;
  }

  try {
    const decoded = Buffer.from(CLIENT_SECRET, "base64").toString("utf8");
    const hmac2 = crypto
      .createHmac("sha256", decoded)
      .update(req.rawBody)
      .digest("base64");
    if (hmac2 === signature) {
      console.log("[PF] 서명 검증 성공 (방법2)");
      return true;
    }
  } catch (e) {}

  try {
    const hmac3 = crypto
      .createHmac("sha256", CLIENT_SECRET)
      .update(JSON.stringify(req.body))
      .digest("base64");
    if (hmac3 === signature) {
      console.log("[PF] 서명 검증 성공 (방법3)");
      return true;
    }
  } catch (e) {}

  console.warn("[PF] 서명 검증 실패 - 수신:", signature);
  const hmacDebug = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(req.rawBody)
    .digest("base64");
  console.warn("[PF] 계산:", hmacDebug);
  return true; // 확인 완료 후 false로 변경
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
        code,
        redirect_uri: REDIRECT_URI,
      }),
      {
        headers: {
          Authorization: `Basic ${Buffer.from(CLIENT_ID + ":" + CLIENT_SECRET).toString("base64")}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      },
    );
    console.log("[PF] 앱 설치 완료:", mallId, tokenResponse.data.access_token);
    res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;">
            <h1>✅ 앱 설치 완료!</h1><p>쇼핑몰 <strong>${mallId}</strong>에 연결되었습니다.</p>
        </body></html>`);
  } catch (err) {
    const errData = err.response ? err.response.data : err.message;
    console.error("[PF] 토큰 발급 실패:", JSON.stringify(errData));
    res
      .status(500)
      .send(`<h1>❌ 설치 실패</h1><p>${JSON.stringify(errData)}</p>`);
  }
}

// ============================================================
// 웹훅 수신 - 회원 (가입 / SNS 연동 / 로그인)
// event_no는 숫자로 오는 경우와 문자열로 오는 경우 모두 대응
// ============================================================
app.post("/webhook/member", function (req, res) {
  console.log("=== MEMBER WEBHOOK ARRIVED ===");
  console.log("[PF] 웹훅 수신 바디:", JSON.stringify(req.body, null, 2));

  if (!verifyCafe24Signature(req)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const data = req.body;
  const eventNo = String(data.event_no); // 숫자/문자열 모두 대응

  console.log("[PF] 웹훅 이벤트 번호:", eventNo);

  if (eventNo === "90032") {
    console.log("[PF] 신규 회원가입");
    handleCompleteSignUp(data, res);
    return;
  }
  if (eventNo === "90063") {
    console.log("[PF] SNS 계정 연동");
    handleSNSAccountLinking(data, res);
    return;
  }
  if (eventNo === "90143") {
    console.log("[PF] 회원 로그인");
    handleSignIn(data, res);
    return;
  }

  res.json({ success: true, skipped: eventNo });
});

// ============================================================
// Complete Sign Up (event_no: 90032)
// 샘플 페이로드:
// resource.member_id, group_no, created_date, member_authentication,
// sms, news_mail, total_mileage, available_mileage,
// recommend_id, use_mobile_app, member_type
// 개인정보 미수집: name, nick_name, birthday, gender, phone, cellphone, email
// ============================================================
function handleCompleteSignUp(data, res) {
  const r = data.resource || {};

  const props = {
    mall_id: r.mall_id || "",
    shop_no: r.event_shop_no || 1,
    $insert_id: "sign_up_" + r.member_id,
    distinct_id: r.member_id || "",

    // 회원 정보
    member_id: r.member_id || "",
    group_no: r.group_no || "",
    created_date: r.created_date || "",
    member_authentication: r.member_authentication || "",
    marketing_sms: r.sms === "T",
    marketing_email: r.news_mail === "T",
    use_mobile_app: r.use_mobile_app === "T",
    member_type: r.member_type || "", // p:개인 c:사업자 f:외국인
    recommend_id: r.recommend_id || "",

    // 적립금
    total_mileage: parseFloat(r.total_mileage) || 0,
    available_mileage: parseFloat(r.available_mileage) || 0,

    // 개인정보 미수집: name, nick_name, birthday, gender, phone, cellphone, email
  };

  // people.set으로 유저 프로퍼티도 업데이트
  mp.people.set(r.member_id, {
    $created: r.created_date || "",
    member_id: r.member_id || "",
    group_no: r.group_no || "",
    marketing_sms: r.sms === "T",
    marketing_email: r.news_mail === "T",
    use_mobile_app: r.use_mobile_app === "T",
    member_type: r.member_type || "",
    recommend_id: r.recommend_id || "",
    total_mileage: parseFloat(r.total_mileage) || 0,
    available_mileage: parseFloat(r.available_mileage) || 0,
  });

  mp.track("Complete Sign Up", props);
  console.log("[PF] Complete Sign Up tracked:", r.member_id);
  res.json({ success: true });
}

// ============================================================
// SNS Account Linking (event_no: 90063)
// 샘플 페이로드: resource.member_id, social_name, social_member_code
// ============================================================
function handleSNSAccountLinking(data, res) {
  const r = data.resource || {};

  const props = {
    mall_id: r.mall_id || "",
    shop_no: r.event_shop_no || 1,
    distinct_id: r.member_id || "",
    member_id: r.member_id || "",
    social_name: r.social_name || "", // kakao, naver 등
    $insert_id: "sns_link_" + r.member_id + "_" + r.social_name,
  };

  mp.track("Link SNS Account", props);
  console.log("[PF] Link SNS Account tracked:", r.member_id, r.social_name);
  res.json({ success: true });
}

// ============================================================
// Sign In (event_no: 90143)
// 샘플 페이로드: resource.member_id, group_name, inflow_name
// inflow_name: "PC" / "Mobile"
// ============================================================
function handleSignIn(data, res) {
  const r = data.resource || {};

  const props = {
    mall_id: r.mall_id || "",
    shop_no: r.event_shop_no || 1,
    distinct_id: r.member_id || "",
    member_id: r.member_id || "",
    group_name: r.group_name || "",
    inflow_name: r.inflow_name || "", // PC / Mobile
    is_mobile: r.inflow_name === "Mobile",
  };

  mp.track("Sign In", props);
  console.log("[PF] Sign In tracked:", r.member_id, "/", r.inflow_name);
  res.json({ success: true });
}

// ============================================================
// 웹훅 수신 - 주문 (생성 / 취소)
// ============================================================
app.post("/webhook/order", function (req, res) {
  console.log("[PF] 웹훅 수신 바디:", JSON.stringify(req.body, null, 2));

  if (!verifyCafe24Signature(req)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const data = req.body;
  const resource = data.resource || {};
  const eventCode = resource.event_code || "";

  console.log("[PF] member 관련 필드:", {
    member_id: resource.member_id,
    buyer_id: resource.buyer_id,
    user_id: resource.user_id,
    buyer_member_id: resource.buyer_member_id,
  });
  console.log("[PF] 이벤트:", eventCode, "주문번호:", resource.order_id);

  if (eventCode === "create_order") {
    handleCompleteOrder(data, res);
    return;
  }

  if (
    eventCode === "cancel_order" ||
    eventCode === "create_order_cancel" ||
    eventCode === "create_order_cancel_all"
  ) {
    handleCancelOrder(data, res);
    return;
  }

  res.json({ success: true, skipped: eventCode });
});

// ============================================================
// payment_gateway 해석 (무통장 등 빈 스트링 대응)
// ============================================================
function resolvePaymentGateway(r) {
  if (r.payment_gateway_name && r.payment_gateway_name.trim())
    return r.payment_gateway_name.trim();
  if (r.easypay_name && r.easypay_name.trim()) return r.easypay_name.trim();
  const methodMap = {
    cash: "무통장입금",
    tcash: "실시간계좌이체",
    icash: "가상계좌",
    card: "카드결제",
    cell: "휴대폰결제",
    mileage: "적립금",
    deposit: "예치금",
    point: "포인트",
    credit: "예치금",
  };
  return methodMap[r.payment_method] || r.payment_method || "";
}

// ============================================================
// Complete Order (event_code: create_order)
// ============================================================
function handleCompleteOrder(data, res) {
  const r = data.resource || {};
  const distinctId = r.member_id ? r.member_id : "guest_" + r.order_id;

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

  const props = {
    mall_id: r.mall_id || "",
    shop_no: r.event_shop_no || 1,
    order_id: r.order_id || "",
    buyer_member_id: r.member_id || "",
    buyer_is_guest: !r.member_id,
    $insert_id: "complete_order_" + r.order_id,
    distinct_id: distinctId,
    order_date: r.order_date || "",
    payment_date: r.payment_date || "",
    buyer_social_service_name: r.buyer_social_service_name || "",
    payment_method: r.payment_method || "",
    payment_gateway: resolvePaymentGateway(r),
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
    order_first_item_name: productNames[0] || "",
    order_item_count: productCodes.length,
    items_detail: items,
    order_detail: {
      payment_amount: parseFloat(r.actual_payment_amount) || 0,
      order_price_amount: parseFloat(r.order_price_amount) || 0,
      mileage_spent_amount: parseFloat(r.mileage_spent_amount) || 0,
      membership_discount_amount: parseFloat(r.membership_discount_amount) || 0,
      shipping_fee: parseFloat(r.shipping_fee) || 0,
    },
    // 개인정보 미수집: buyer_name, buyer_email, buyer_cellphone 제외
  };

  mp.track("Complete Order", props);
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
    distinct_id: distinctId,
    buyer_is_guest: !r.member_id,
    $insert_id: "cancel_order_" + r.order_id,
    cancel_date: r.cancel_date || r.order_date || "",
    payment_method: r.payment_method || "",
    payment_gateway: resolvePaymentGateway(r),
    order_price_amount: parseFloat(r.order_price_amount) || 0,
    actual_payment_amount: parseFloat(r.actual_payment_amount) || 0,
    refund_amount: parseFloat(r.refund_amount) || 0,
    cancel_reason: r.cancel_reason || "",
    buyer_social_service_name: r.buyer_social_service_name || "",
    // 개인정보 미수집: buyer_name, buyer_cellphone 제외
  };

  mp.track("Cancel Order", props);
  console.log("[PF] Cancel Order tracked:", r.order_id);
  res.json({ success: true });
}

// ============================================================
// 헬스체크 & 디버그
// ============================================================
/*
app.get("/health", function (req, res) {
  res.json({ status: "ok", time: new Date().toISOString() });
});
*/
app.post("/webhook/debug", function (req, res) {
  console.log("[DEBUG] Headers:", JSON.stringify(req.headers, null, 2));
  console.log("[DEBUG] Body:", JSON.stringify(req.body, null, 2));
  res.json({ received: true });
});

app.listen(PORT, function () {
  console.log("[PF] 서버 실행 중, 포트:", PORT);
});
