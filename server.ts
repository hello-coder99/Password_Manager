import { spawn, type ChildProcess } from "child_process";
import express from "express";
import http from "http";
import path from "path";
import { createServer as createViteServer } from "vite";

const PORT = 3000;
const FLASK_PORT = 5000;
const FLASK_HOST = "127.0.0.1";

let flaskProcess: ChildProcess | null = null;

function startFlaskBackend(): void {
  const env = {
    ...process.env,
    FLASK_ENV: "development",
    PYTHONUNBUFFERED: "1",
    TRUSTED_PROXY_COUNT: "1",
    CSP_FRAME_ANCESTORS: "'self' https://*.google.com https://*.run.app",
  };

  flaskProcess = spawn("python3", ["wsgi.py"], {
    cwd: process.cwd(),
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  flaskProcess.stdout?.on("data", (chunk: Buffer) => {
    process.stdout.write(`[flask] ${chunk.toString()}`);
  });

  flaskProcess.stderr?.on("data", (chunk: Buffer) => {
    process.stderr.write(`[flask] ${chunk.toString()}`);
  });

  flaskProcess.on("exit", (code) => {
    if (code !== 0 && code !== null) {
      console.error(`[flask] exited with code ${code}, restarting in 2s...`);
      setTimeout(startFlaskBackend, 2000);
    }
  });
}

async function waitForFlaskReady(timeoutMs = 15000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ready = await new Promise<boolean>((resolve) => {
      const req = http.get(
        {
          hostname: FLASK_HOST,
          port: FLASK_PORT,
          path: "/api/health",
          timeout: 1000,
        },
        (res) => {
          res.resume();
          resolve(res.statusCode === 200 || res.statusCode === 503);
        }
      );
      req.on("error", () => resolve(false));
      req.on("timeout", () => {
        req.destroy();
        resolve(false);
      });
    });
    if (ready) return;
    await new Promise((r) => setTimeout(r, 250));
  }
}

async function startServer() {
  startFlaskBackend();
  await waitForFlaskReady();

  const app = express();
  app.disable("x-powered-by");

  // Reverse proxy /api/* to the Python Flask backend on 127.0.0.1:5000
  app.use("/api", (req, res) => {
    const isHttpsProxy =
      req.headers["x-forwarded-proto"] === "https" ||
      (process.env.APP_URL || "").startsWith("https://");

    const proxyHeaders: http.OutgoingHttpHeaders = {
      ...req.headers,
      host: req.headers.host || `127.0.0.1:${PORT}`,
      "x-forwarded-for":
        (req.headers["x-forwarded-for"] as string) ||
        req.socket.remoteAddress ||
        "127.0.0.1",
      "x-forwarded-proto": isHttpsProxy ? "https" : "http",
    };

    const proxyReq = http.request(
      {
        hostname: FLASK_HOST,
        port: FLASK_PORT,
        path: `/api${req.url}`,
        method: req.method,
        headers: proxyHeaders,
      },
      (proxyRes) => {
        const outHeaders: http.OutgoingHttpHeaders = { ...proxyRes.headers };

        // Ensure session cookies function inside the HTTPS preview iframe (CHIPS / Partitioned)
        if (isHttpsProxy && outHeaders["set-cookie"]) {
          const rawCookies = Array.isArray(outHeaders["set-cookie"])
            ? outHeaders["set-cookie"]
            : [String(outHeaders["set-cookie"])];
          outHeaders["set-cookie"] = rawCookies.map((cookieStr) => {
            let updated = cookieStr.replace(
              /SameSite=Lax/gi,
              "SameSite=None; Secure; Partitioned"
            );
            if (!/SameSite=/i.test(updated)) {
              updated += "; SameSite=None; Secure; Partitioned";
            }
            return updated;
          });
        }

        res.writeHead(proxyRes.statusCode || 500, outHeaders);
        proxyRes.pipe(res, { end: true });
      }
    );

    proxyReq.on("error", () => {
      if (!res.headersSent) {
        res.status(502).json({
          error: "Flask API backend is temporarily unreachable.",
          code: "BAD_GATEWAY",
        });
      }
    });

    req.pipe(proxyReq, { end: true });
  });

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*all", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`AegisVault server listening on http://0.0.0.0:${PORT}`);
  });
}

process.on("SIGTERM", () => {
  flaskProcess?.kill();
  process.exit(0);
});

startServer();
