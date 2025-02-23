const express = require('express');
const fetch = require('node-fetch');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// Configurações do app (substitua pelos seus valores do Painel de Parceiros Shopify)
const API_KEY = 'SEU_CLIENT_ID'; // Substitua pelo Client ID do Painel de Parceiros Shopify
const API_SECRET = 'SEU_CLIENT_SECRET'; // Substitua pelo Client Secret do Painel de Parceiros Shopify
const APP_URL = 'https://rastreio-novo-id.vercel.app'; // Substitua pela URL que o Vercel gerar

// Armazenamento temporário (use um banco em produção)
const shopConfigs = {};

// Rota de instalação (OAuth)
app.get('/shopify/install', (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send('Shop não fornecido');

  const nonce = crypto.randomBytes(16).toString('hex');
  const redirectUri = `${APP_URL}/api/auth/callback`;
  const scopes = 'read_orders,write_orders';
  const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${API_KEY}&scope=${scopes}&redirect_uri=${redirectUri}&state=${nonce}`;

  res.redirect(installUrl);
});

// Callback do OAuth
app.get('/api/auth/callback', async (req, res) => {
  const { shop, code } = req.query;
  if (!shop || !code) return res.status(400).send('Parâmetros inválidos');

  const accessTokenUrl = `https://${shop}/admin/oauth/access_token`;
  const payload = {
    client_id: API_KEY,
    client_secret: API_SECRET,
    code
  };

  try {
    const response = await fetch(accessTokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const { access_token } = await response.json();
    shopConfigs[shop] = { accessToken: access_token };
    res.redirect(`/api/configure?shop=${shop}`); // Redireciona pra configuração
  } catch (error) {
    res.status(500).send('Erro ao autenticar');
  }
});

// Rota de configuração (token do Melhor Envio)
app.post('/api/configure', (req, res) => {
  const { shop, accessToken, melhorEnvioToken } = req.body;
  if (!shopConfigs[shop]) shopConfigs[shop] = {};
  shopConfigs[shop].melhorEnvioToken = melhorEnvioToken;
  res.json({ message: 'Configuração salva' });
});

// Rota de rastreio
app.post('/api/track', async (req, res) => {
  const { shop, accessToken, searchType, inputValue, inputEmail } = req.body;
  const config = shopConfigs[shop];
  if (!config || !config.accessToken || !config.melhorEnvioToken) {
    return res.status(400).json({ error: 'Loja não configurada' });
  }

  try {
    let order;
    if (searchType === 'order') {
      const orderResponse = await fetch(`https://${shop}/admin/api/2023-10/orders.json?name=${encodeURIComponent(inputValue)}`, {
        headers: { 'X-Shopify-Access-Token': accessToken }
      });
      const orderData = await orderResponse.json();
      order = orderData.orders.find(o => o.name === inputValue && (!o.email || o.email.toLowerCase() === inputEmail.toLowerCase()));
      if (!order) throw new Error('Pedido não encontrado');
    } else {
      const fulfillmentResponse = await fetch(`https://${shop}/admin/api/2023-10/fulfillments.json`, {
        headers: { 'X-Shopify-Access-Token': accessToken }
      });
      const fulfillmentData = await fulfillmentResponse.json();
      const matchingFulfillment = fulfillmentData.fulfillments.find(f => f.tracking_number === inputValue);
      if (!matchingFulfillment) throw new Error('Rastreio não encontrado');
      const orderResponse = await fetch(`https://${shop}/admin/api/2023-10/orders/${matchingFulfillment.order_id}.json`, {
        headers: { 'X-Shopify-Access-Token': accessToken }
      });
      order = (await orderResponse.json()).order;
    }

    let trackingInfo = {};
    if (order.fulfillments.length > 0 && order.fulfillments[0].tracking_number) {
      const trackingResponse = await fetch('https://api.melhorenvio.com.br/api/v2/me/shipment/tracking', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${config.melhorEnvioToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ tracking_codes: [order.fulfillments[0].tracking_number] })
      });
      const trackingData = await trackingResponse.json();
      trackingInfo = trackingData[order.fulfillments[0].tracking_number] || {};
    }

    res.json({ order, trackingInfo });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = app; // Exporta pra Vercel