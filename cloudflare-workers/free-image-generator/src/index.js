export default {
  async fetch(request, env) {
    // Define standard CORS headers to allow cross-origin requests from localhost
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
    };

    // Handle the browser's Preflight request (OPTIONS) immediately
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    // Process the actual generation request
    if (request.method === "POST") {
      try {
        // Validate the presence of the Authorization header
        const authHeader = request.headers.get("Authorization");
        if (!authHeader) {
          return new Response(JSON.stringify({ error: "Missing API Key" }), {
            status: 401,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // Parse the incoming JSON payload from the frontend
        const { prompt } = await request.json();
        if (!prompt) {
          return new Response(JSON.stringify({ error: "Prompt is required" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // List of models to rotate or use as fallback alternatives
        const models = [
          '@cf/black-forest-labs/flux-1-schnell',
          '@cf/stabilityai/stable-diffusion-xl-base-1.0',
          '@cf/lykon/dreamshaper-8-lcm'
        ];

        let aiResponse = null;
        let chosenModel = "";
        let lastError = null;

        // Try executing models sequentially until one succeeds
        for (const model of models) {
          try {
            chosenModel = model;
            aiResponse = await env.AI_BINDING.run(model, { prompt });
            if (aiResponse) break; // Exit loop if the model successfully responded
          } catch (err) {
            console.error(`Model ${model} failed, trying next... Error:`, err);
            lastError = err;
          }
        }

        // If all models failed, throw an explicit execution error
        if (!aiResponse) {
          throw new Error(`All AI models failed to execute. Last error: ${lastError?.message}`);
        }

        // CRITICAL FIX: Cloudflare AI models return an object: { image: "base64_string..." }
        // We must convert this base64 string into a raw binary buffer for the frontend to receive an actual JPEG file
        if (aiResponse.image) {
          const binaryString = atob(aiResponse.image);
          const imgBuffer = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            imgBuffer[i] = binaryString.charCodeAt(i);
          }

          // Return the raw binary image data to the frontend
          return new Response(imgBuffer, {
            status: 200,
            headers: {
              ...corsHeaders,
              "Content-Type": "image/jpeg",
              "X-Generated-By-Model": chosenModel
            },
          });
        } else {
          throw new Error("The AI model returned a valid response but it did not contain an 'image' field.");
        }

      } catch (err) {
        // Catch any execution errors and return them as JSON with CORS headers included
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // Fallback response for unhandled HTTP methods
    return new Response("Method not allowed", { status: 405, headers: corsHeaders });
  }
};
