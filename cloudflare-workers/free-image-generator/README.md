
# 🌌 AI Studio - Free Image Generation API & Web Interface

A lightweight, high-performance **Cloudflare Worker** that provides a secure Text-to-Image Generation API with an automated multi-model rotation and fallback mechanism. If a primary model is saturated or hits Cloudflare AI rate limits, the Worker automatically falls back to alternative models. It includes a responsive web dashboard with modern skeleton loading states.

## 📂 Project Structure

```text
├── src/
│   └── index.js          # Cloudflare Worker core logic
├── demo.html             # Web dashboard frontend interface
├── wrangler.jsonc        # Cloudflare configuration file
└── package.json          # Node.js project dependencies
```

---

## 🚀 Getting Started & Deployment

### 1. Configure Wrangler
Ensure your `wrangler.jsonc` defines the required `AI_BINDING` and marks the `API_KEY` as a mandatory secret:

```jsonc
{
	"$schema": "node_modules/wrangler/config-schema.json",
	"name": "free-image-generator",
	"main": "src/index.js",
	"compatibility_date": "2026-09-25",
	"observability": { "enabled": true },
	"upload_source_maps": true,
	"ai": {
		"binding": "AI_BINDING"
	},
	"secrets": {
		"required": ["API_KEY"]
	}
}
```

### 2. Set Up the Security API Key
Since `API_KEY` is a required secret, you must upload it to Cloudflare before running the deployment command. 

Run this command in your terminal and type your custom security token when prompted:
```bash
npx wrangler secret put API_KEY
```

### 3. Deploy to Cloudflare
Once the secret is set, publish your Worker to the Cloudflare global network:
```bash
npx wrangler deploy
```

---

## 💻 Local Development

To test the application locally on your machine before pushing it live:

1. Create a `.dev.vars` file in the root directory (this file is automatically ignored by git):
   ```env
   API_KEY="your_local_test_key"
   ```

2. Start the Wrangler local emulation server:
   ```bash
   npx wrangler dev
   ```

3. Open `demo.html` and update the `API_URL` constant to match your local address (usually `http://localhost:8787/`).

---

## 🔌 API Reference

### Generate Image
- **URL:** `/`
- **Method:** `POST`
- **Headers:**
  - `Content-Type: application/json`
  - `Authorization: Bearer <YOUR_API_KEY>`
- **Request Body:**
  ```json
  {
    "prompt": "A futuristic cyberpunk city, neon lighting, 8k resolution"
  }
  ```

### Response Meta Headers
When an image is successfully generated, the response includes custom tracking headers:
```http
Content-Type: image/jpeg
X-Generated-By-Model: @cf/blackforestlabs/ux-1-schnell
Access-Control-Allow-Origin: *
```

---

## 🎨 Web Frontend Setup
1. Open `demo.html` in your favorite code editor.
2. Locate the following line inside the `<script>` tag:
   ```javascript
   const API_URL = "https://workers.dev";
   ```
3. Replace it with your deployed Cloudflare Worker production URL.
4. Launch `demo.html` in any browser, input your `API_KEY`, type a prompt, and hit **Generate**!
