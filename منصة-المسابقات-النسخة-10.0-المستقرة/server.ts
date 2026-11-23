import 'dotenv/config';
import express from 'express';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { createServer as createViteServer } from 'vite';
import { WebSocketServer, WebSocket } from 'ws';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import { TriviaEngine } from './server/engine.ts';
import process from 'node:process';

// ─── Security: Helmet CSP ──────────────────────────────────────────────
const cspDirectives = {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'"],
  styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:', 'https:'],
  mediaSrc: ["'self'", 'https:'],
  connectSrc: ["'self'", 'ws:', 'wss:'],
  fontSrc: ["'self'", 'data:'],
  objectSrc: ["'none'"],
  baseUri: ["'self'"],
  formAction: ["'self'"],
  frameAncestors: ["'none'"],
};

async function startServer(): Promise<void> {
  const PORT = Number(process.env.PORT) || 3000;
  const app = express();

  // ─── Security Middleware ─────────────────────────────────────────────
  app.use(helmet({
    contentSecurityPolicy: { directives: cspDirectives },
    crossOriginEmbedderPolicy: false, // needed for WebSocket
    hsts: process.env.NODE_ENV === 'production' ? { maxAge: 31536000 } : false,
  }));

  // ─── Rate Limiting ───────────────────────────────────────────────────
  const apiLimiter = rateLimit({
    windowMs: 60_000, // 1 minute
    max: 120,         // 120 requests per minute per IP
    message: { status: 'RATE_LIMITED', message: '⚠️ عدد الطلبات كبير جداً، يرجى الانتظار' },
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use('/api/', apiLimiter);

  const authLimiter = rateLimit({
    windowMs: 15 * 60_000, // 15 minutes
    max: 10,               // 10 attempts per 15 min
    message: { status: 'RATE_LIMITED', message: '⚠️ محاولات تسجيل دخول كثيرة، يرجى المحاولة لاحقاً' },
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use(['/api/host/answers', '/api/host/team-tokens', '/api/team/verify', '/api/team/traps'], authLimiter);

  app.use(express.json({ limit: '5mb' }));
  app.use(cookieParser(process.env.COOKIE_SECRET || 'dev-secret-change-in-production'));

  // ─── Secure Cookie Options ───────────────────────────────────────────────
  const isProd = process.env.NODE_ENV === 'production';
  const cookieOptions = {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax' as const,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/',
  };

  const engine = new TriviaEngine();

  // ─── Audit Logging Middleware ──────────────────────────────────────────
  function auditLog(event: string, details: Record<string, unknown> = {}): void {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      ip: details.ip || 'unknown',
      userAgent: details.userAgent || 'unknown',
      ...details,
    };
    // Remove sensitive data
    delete logEntry.token;
    delete logEntry.pin;
    delete logEntry.password;
    console.log('[AUDIT]', JSON.stringify(logEntry));
  }

  // ─── Middleware to extract client info ─────────────────────────────────
  function addClientInfo(req: express.Request, _res: express.Response, next: express.NextFunction): void {
    (req as express.Request & { clientIp?: string; clientUA?: string }).clientIp =
      req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      'unknown';
    (req as express.Request & { clientUA?: string }).clientUA = req.headers['user-agent'] || 'unknown';
    next();
  }
  app.use(addClientInfo);

  // ─── Health & State ──────────────────────────────────────────────────
  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, now: Date.now() });
  });

  app.get('/api/state', (_req, res) => {
    res.json({
      state: engine.getSanitizedState(),
      questions: engine.getStrippedQuestions(),
    });
  });

  app.get('/api/questions', (_req, res) => {
    res.json({ questions: engine.getStrippedQuestions() });
  });

  // ─── Actions ─────────────────────────────────────────────────────────
  app.post('/api/action', (req, res) => {
    const body = (req.body || {}) as { action?: string; payload?: Record<string, unknown> };
    if (!body.action) {
      res.status(400).json({ status: 'BAD_REQUEST', message: 'Missing action name' });
      return;
    }
    const result = engine.handleAction(body.action, body.payload || {});
    res.json(result);
  });

  // ─── Host/Admin Endpoints (PIN required in production) ──────────────
  app.post('/api/host/answers', (req, res) => {
    const body = (req.body || {}) as { pin?: string };
    const providedPin = typeof body.pin === 'string' ? body.pin : '';
    const clientIp = (req as express.Request & { clientIp?: string }).clientIp || 'unknown';
    const clientUA = (req as express.Request & { clientUA?: string }).clientUA || 'unknown';

    // In production, require PIN (cannot be disabled)
    if (isProd && !providedPin) {
      auditLog('HOST_ANSWERS_ATTEMPT_NO_PIN', { ip: clientIp, userAgent: clientUA });
      res.status(401).json({ status: 'PIN_REQUIRED', message: '🔐 رمز حماية المذيع مطلوب في بيئة الإنتاج' });
      return;
    }

    const result = engine.getHostAnswers(providedPin);
    if (result.status === 'INVALID_PIN') {
      auditLog('HOST_ANSWERS_INVALID_PIN', { ip: clientIp, userAgent: clientUA });
      res.status(401).json(result);
      return;
    }

    // Set secure cookie for host session
    res.cookie('host_auth', 'verified', cookieOptions);
    auditLog('HOST_ANSWERS_SUCCESS', { ip: clientIp, userAgent: clientUA });
    res.json(result);
  });

  app.post('/api/host/team-tokens', (req, res) => {
    // Verify host authentication via cookie
    if (isProd && req.cookies.host_auth !== 'verified') {
      const clientIp = (req as express.Request & { clientIp?: string }).clientIp || 'unknown';
      auditLog('HOST_TEAM_TOKENS_UNAUTHORIZED', { ip: clientIp });
      res.status(401).json({ status: 'UNAUTHORIZED', message: '🔐 يرجى التحقق من رمز المذيع أولاً' });
      return;
    }
    res.json(engine.getHostTeamTokens());
  });

  // ─── Team Endpoints ──────────────────────────────────────────────────
  app.post('/api/team/verify', (req, res) => {
    const body = (req.body || {}) as { teamId?: string; token?: string };
    // Support both cookie and body for backward compatibility
    const teamId = typeof body.teamId === 'string' ? body.teamId : '';
    const token = typeof body.token === 'string' ? body.token : (req.cookies.team_token as string | undefined);
    const clientIp = (req as express.Request & { clientIp?: string }).clientIp || 'unknown';

    if (!teamId || !token) {
      auditLog('TEAM_VERIFY_MISSING_CREDENTIALS', { ip: clientIp, teamId });
      res.status(400).json({ status: 'BAD_REQUEST', message: 'مطلوب رقم الفريق والرمز' });
      return;
    }

    const result = engine.verifyTeamToken(teamId, token);
    if (!result.valid) {
      auditLog('TEAM_VERIFY_INVALID_TOKEN', { ip: clientIp, teamId });
      res.status(403).json(result);
      return;
    }

    // Set secure cookie for team session
    res.cookie('team_token', token, cookieOptions);
    res.cookie('team_id', teamId, cookieOptions);
    auditLog('TEAM_VERIFY_SUCCESS', { ip: clientIp, teamId });
    res.json(result);
  });

  app.post('/api/team/traps', (req, res) => {
    const body = (req.body || {}) as { teamId?: string; token?: string };
    // Support both cookie and body for backward compatibility
    const teamId = typeof body.teamId === 'string' ? body.teamId : (req.cookies.team_id as string | undefined);
    const token = typeof body.token === 'string' ? body.token : (req.cookies.team_token as string | undefined);
    const clientIp = (req as express.Request & { clientIp?: string }).clientIp || 'unknown';

    if (!teamId || !token) {
      auditLog('TEAM_TRAPS_MISSING_CREDENTIALS', { ip: clientIp, teamId });
      res.status(400).json({ status: 'BAD_REQUEST', message: 'مطلوب رقم الفريق والرمز' });
      return;
    }

    const result = engine.getTeamTraps(teamId, token);
    if (result.status === 'INVALID_TOKEN') {
      auditLog('TEAM_TRAPS_INVALID_TOKEN', { ip: clientIp, teamId });
      res.status(403).json(result);
      return;
    }

    auditLog('TEAM_TRAPS_SUCCESS', { ip: clientIp, teamId });
    res.json(result);
  });

  // ─── Static / SPA ────────────────────────────────────────────────────
  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  // ─── HTTP Server + WebSocket ────────────────────────────────────────
  const httpServer = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true });

  // Track connections per IP for WS rate limiting
  const wsConnectionsPerIp = new Map<string, number>();
  const MAX_WS_PER_IP = 10;

  // ─── HTTPS Redirect Middleware (for production) ──────────────────────────
  if (isProd) {
    app.use((req, res, next) => {
      const proto = req.headers['x-forwarded-proto'];
      if (proto !== 'https') {
        const host = req.headers.host;
        const url = `https://${host}${req.url}`;
        auditLog('HTTP_REDIRECT_TO_HTTPS', { ip: (req as any).clientIp, url });
        return res.redirect(301, url);
      }
      next();
    });
  }

  httpServer.on('upgrade', (request, socket, head) => {
    try {
      const reqUrl = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);
      if (reqUrl.pathname === '/ws') {
        // Get client IP
        const ip = request.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                   request.socket.remoteAddress ||
                   'unknown';

        // Enforce per-IP WS connection limit
        const current = wsConnectionsPerIp.get(ip) || 0;
        if (current >= MAX_WS_PER_IP) {
          auditLog('WS_CONNECTION_LIMIT_EXCEEDED', { ip, limit: MAX_WS_PER_IP });
          socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
          socket.destroy();
          return;
        }

        // Parse cookies from upgrade request for auth
        const cookieHeader = request.headers.cookie || '';
        const cookies = Object.fromEntries(
          cookieHeader.split(';').map(c => c.trim().split('=')).filter(([k]) => k)
        );

        wss.handleUpgrade(request, socket, head, (ws) => {
          wsConnectionsPerIp.set(ip, current + 1);
          const trackedWs = ws as WebSocket & { _clientIp?: string; _teamId?: string; _authenticated?: boolean };
          trackedWs._clientIp = ip;
          trackedWs._teamId = cookies.team_id;
          trackedWs._authenticated = !!cookies.team_token;
          wss.emit('connection', trackedWs, request);
        });
      }
    } catch {
      socket.destroy();
    }
  });

  engine.subscribe((safeState, safeQuestions) => {
    const payload = JSON.stringify({
      type: 'state:sync',
      state: safeState,
      questions: safeQuestions,
      serverNow: Date.now(), // include server timestamp for client clock sync
    });
    for (const client of wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    }
  });

  // ─── WebSocket Heartbeat with Backpressure Handling ─────────────────
  const heartbeatInterval = setInterval(() => {
    for (const client of wss.clients) {
      const tracked = client as WebSocket & { isAlive?: boolean; _clientIp?: string };
      if (tracked.isAlive === false) {
        // Cleanup IP tracking
        if (tracked._clientIp) {
          const count = wsConnectionsPerIp.get(tracked._clientIp) || 1;
          wsConnectionsPerIp.set(tracked._clientIp, Math.max(0, count - 1));
        }
        tracked.terminate();
        continue;
      }
      // Backpressure check: don't ping if client's send buffer is full
      if (tracked.bufferedAmount > 16 * 1024) {
        if (tracked._clientIp) {
          const count = wsConnectionsPerIp.get(tracked._clientIp) || 1;
          wsConnectionsPerIp.set(tracked._clientIp, Math.max(0, count - 1));
        }
        tracked.terminate();
        continue;
      }
      tracked.isAlive = false;
      tracked.ping();
    }
  }, 25000);

  wss.on('close', () => {
    clearInterval(heartbeatInterval);
  });

  wss.on('connection', (ws) => {
    const tracked = ws as WebSocket & { isAlive?: boolean; _clientIp?: string; _teamId?: string; _authenticated?: boolean };
    tracked.isAlive = true;
    ws.on('pong', () => {
      tracked.isAlive = true;
    });

    // Require authentication for WebSocket in production
    if (isProd && !tracked._authenticated) {
      auditLog('WS_CONNECTION_UNAUTHENTICATED', { ip: tracked._clientIp });
      ws.close(4001, 'Authentication required');
      return;
    }

    if (tracked._teamId) {
      auditLog('WS_CONNECTION_AUTHENTICATED', { ip: tracked._clientIp, teamId: tracked._teamId });
    }

    ws.send(
      JSON.stringify({
        type: 'state:sync',
        state: engine.getSanitizedState(),
        questions: engine.getStrippedQuestions(),
        serverNow: Date.now(),
      })
    );

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString()) as {
          type?: string;
          requestId?: string;
          action?: string;
          payload?: Record<string, unknown>;
        };
        if (msg.type === 'action' && msg.action) {
          const result = engine.handleAction(msg.action, msg.payload || {});
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(
              JSON.stringify({
                type: 'action:ack',
                requestId: msg.requestId || null,
                result,
                serverNow: Date.now(),
              })
            );
          }
        } else if (msg.type === 'sync:request') {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(
              JSON.stringify({
                type: 'state:sync',
                state: engine.getSanitizedState(),
                questions: engine.getStrippedQuestions(),
                serverNow: Date.now(),
              })
            );
          }
        }
      } catch (err) {
        console.error('WS message parse error:', err);
      }
    });

    ws.on('close', () => {
      if (tracked._clientIp) {
        const count = wsConnectionsPerIp.get(tracked._clientIp) || 1;
        wsConnectionsPerIp.set(tracked._clientIp, Math.max(0, count - 1));
      }
    });
  });

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Trivia Multi-Screen Real-Time Server running on http://0.0.0.0:${PORT}`);
    console.log(`WebSocket endpoint: ws://0.0.0.0:${PORT}/ws`);
    console.log(`Security: Helmet CSP + Rate Limiting + WS Connection Limits (${MAX_WS_PER_IP}/IP)`);
  });

  // ─── Graceful Shutdown ───────────────────────────────────────────────
  const shutdown = async (signal: string) => {
    console.log(`\n${signal} received, shutting down gracefully...`);
    engine.shutdown();
    httpServer.close(() => {
      console.log('HTTP server closed.');
      process.exit(0);
    });
    // Force close after 5 seconds
    setTimeout(() => {
      console.error('Forced shutdown after timeout');
      process.exit(1);
    }, 5000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});