import dotenv from 'dotenv';
dotenv.config();
process.on('uncaughtException', (err) => {
  console.error('❌ UNCAUGHT EXCEPTION:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('❌ UNHANDLED REJECTION:', reason);
});

import express, { Request, Response } from 'express';
import path from 'path';
import { prisma } from './config/db';
import { adminRouter } from './routes/admin.routes';
import { authRouter } from './routes/auth.routes';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const publicDir = path.join(process.cwd(), 'public');
app.use(express.static(publicDir));

app.get('/', (req: Request, res: Response) => {
  res.redirect('/admin/login');
});

app.get('/admin', (req: Request, res: Response) => {
  res.redirect('/admin/login');
});

app.get('/admin/login', (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'admin', 'login.html'));
});

app.get('/admin/dashboard', (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'admin', 'dashboard.html'));
});

app.get('/admin/add-admin', (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'admin', 'add-admin.html'));
});

app.get('/admin/Admin-management', (req: Request, res: Response) => {
  res.sendFile(
    path.join(publicDir, 'admin', 'admin-management.html')
  );
});

app.get('/login.html', (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'login.html'));
});

app.get('/signup.html', (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'signup.html'));
});

app.use('/api/admin', adminRouter);
app.use('/api/auth', authRouter);   

app.get('/api/health', async (req: Request, res: Response) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({
      status: 'success',
      database: 'MySQL (XAMPP)',
      message: 'Backend is connected to MySQL Database on XAMPP successfully!',
      timestamp: new Date(),
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      database: 'MySQL (XAMPP)',
      message: 'Database connection failed',
      error: (error as Error).message,
    });
  }
});

app.post('/api/users', async (req: Request, res: Response) => {
  try {
    const { name, email, passwordHash, role } = req.body;
    const user = await prisma.user.create({
      data: {
        name,
        email,
        passwordHash,
        role: role || 'USER',
        updatedAt: new Date(),
      },
    });
    res.status(201).json({
      message: 'User created successfully!',
      user,
    });
  } catch (error) {
    res.status(400).json({
      error: 'Failed to create user',
      details: (error as Error).message,
    });
  }
});

app.post('/api/scans/start', async (req: Request, res: Response) => {
  try {
    const { targetId } = req.body;
    const scan = await prisma.scan.create({
      data: {
        targetId: Number(targetId),
        status: 'RUNNING',
        startedAt: new Date(),
        updatedAt: new Date(),
      },
    });
    res.status(201).json({
      message: 'Scan started!',
      scan,
    });
  } catch (error) {
    res.status(400).json({
      error: 'Failed to start scan',
      details: (error as Error).message,
    });
  }
});

app.listen(port, () => {
  console.log('\n======================================================');
  console.log(`🚀 Vulnerability Scanner Server running on http://localhost:${port}`);
  console.log(`🔐 Admin Login Page: http://localhost:${port}/admin/login`);
  console.log(`📊 Admin Dashboard: http://localhost:${port}/admin/dashboard`);
  console.log(`👤 User Signup: http://localhost:${port}/signup.html`);
  console.log(`👤 User Login: http://localhost:${port}/login.html`);
  console.log(`👉 Database Health Check: http://localhost:${port}/api/health`);
  console.log('🗄️ MySQL database: vuln_scanner');
  console.log('======================================================\n');
});
