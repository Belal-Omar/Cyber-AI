import { Router, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../config/db';
import { requireAdminAuth, AuthenticatedRequest } from '../middlewares/auth.middleware';

export const adminRouter = Router();

const JWT_SECRET = process.env.JWT_SECRET || 'vuln_scanner_admin_super_secret_jwt_key_2026';

/**
 * POST /api/admin/login
 * Admin Login Endpoint
 * - Verifies user against the Database (MySQL on XAMPP)
 * - Verifies password using bcrypt hash
 * - Strictly enforces: user.role === 'ADMIN'
 * - Records login in AuditLog table
 */
adminRouter.post('/login', async (req, res): Promise<void> => {
  try {
    const { email, password } = req.body;

    // 1. Validate request body
    if (!email || !password) {
      res.status(400).json({
        success: false,
        error: 'Email and password are required.',
      });
      return;
    }

    // 2. Fetch user from Database (No credentials hardcoded in the code!)
    const user = await prisma.user.findUnique({
      where: { email: email.trim().toLowerCase() },
    });

    if (!user) {
      res.status(401).json({
        success: false,
        error: 'Invalid credentials. User not found in database.',
      });
      return;
    }

    // 3. Verify password hash using bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      res.status(401).json({
        success: false,
        error: 'Invalid credentials. Password does not match.',
      });
      return;
    }

    // 4. Strict Role Verification: must have role === 'ADMIN'
    if (user.role.toUpperCase() !== 'ADMIN') {
      // Record unauthorized attempt in audit log
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'UNAUTHORIZED_ADMIN_LOGIN_ATTEMPT',
          details: `User with role '${user.role}' attempted to access admin portal.`,
        },
      });

      res.status(403).json({
        success: false,
        error: `Access Denied: Administrator role required. Your account role is '${user.role}'.`,
      });
      return;
    }

    // 5. Check if user account is active
    if (!user.isActive) {
      res.status(403).json({
        success: false,
        error: 'Account is deactivated. Please contact system administrator.',
      });
      return;
    }

    // 6. Update last login timestamp in DB
    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    // 7. Write an audit log entry into the database
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'ADMIN_LOGIN_SUCCESS',
        details: `Admin ${user.name} logged in successfully via Admin Portal.`,
      },
    });

    // 8. Generate JWT token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // 9. Send success response with token and user details
    res.json({
      success: true,
      message: 'Admin authentication successful! Welcome back.',
      token,
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
        lastLoginAt: updatedUser.lastLoginAt,
      },
    });
  } catch (error) {
    console.error('Admin Login Error:', error);
    res.status(500).json({
      success: false,
      error: 'An unexpected server error occurred during login.',
      details: (error as Error).message,
    });
  }
});

/**
 * GET /api/admin/me
 * Returns current authenticated admin's data
 */
adminRouter.get('/me', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        isActive: true,
        lastLoginAt: true,
        createdAt: true,
      },
    });

    if (!user) {
      res.status(404).json({ success: false, error: 'User not found in database.' });
      return;
    }

    res.json({
      success: true,
      user,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to retrieve profile.' });
  }
});

/**
 * GET /api/admin/stats
 * Returns statistics for the Admin Dashboard
 */
adminRouter.get('/stats', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const [userCount, projectCount, targetCount, scanCount, vulnCount] = await Promise.all([
      prisma.user.count(),
      prisma.project.count(),
      prisma.target.count(),
      prisma.scan.count(),
      prisma.vulnerability.count(),
    ]);

    res.json({
      success: true,
    stats: {
  totalUsers: userCount,
  totalAdmin: await prisma.user.count({
    where: { role: 'ADMIN' },
  }),
  totalProjects: projectCount,
  totalTargets: targetCount,
  totalScans: scanCount,
  totalVulnerabilities: vulnCount,
  database: 'MySQL (XAMPP)',
},
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch admin stats.' });
  }
});
/**

 * GET /api/admin/users

 * Returns list of administrators only

 */

adminRouter.get('/users', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {

  try {

    const users = await prisma.user.findMany({

      where: {

        role: 'ADMIN',

      },

      select: {

        id: true,

        name: true,

        email: true,

        role: true,

        isActive: true,

        lastLoginAt: true,

        createdAt: true,

      },

      orderBy: { id: 'asc' },

    });

    res.json({ success: true, users });

  } catch (error) {

    res.status(500).json({ success: false, error: 'Failed to fetch admin list.' });

  }

});

adminRouter.patch(

  '/users/:id/status',

  requireAdminAuth,

  async (req: AuthenticatedRequest, res: Response): Promise<void> => {

    try {

      const userId = Number(req.params.id);

      const { isActive } = req.body;

      const currentAdminId = req.user?.id;

      if (!Number.isSafeInteger(userId) || userId <= 0) {

        res.status(400).json({

          success: false,

          error: 'Invalid user ID.',

        });

        return;

      }

      if (typeof isActive !== 'boolean') {

        res.status(400).json({

          success: false,

          error: 'isActive must be true or false.',

        });

        return;

      }

      if (!currentAdminId) {

        res.status(401).json({

          success: false,

          error: 'Administrator identity is missing.',

        });

        return;

      }

      if (userId === currentAdminId && !isActive) {

        res.status(400).json({

          success: false,

          error: 'You cannot deactivate your own account.',

        });

        return;

      }

      const targetUser = await prisma.user.findUnique({

        where: { id: userId },

        select: {

          id: true,

          name: true,

          role: true,

          isActive: true,

        },

      });

      if (!targetUser) {

        res.status(404).json({

          success: false,

          error: 'User not found.',

        });

        return;

      }

      if (targetUser.isActive === isActive) {

        res.json({

          success: true,

          message: 'User status is already up to date.',

        });

        return;

      }

      if (

        !isActive &&

        targetUser.role.toUpperCase() === 'ADMIN' &&

        targetUser.isActive

      ) {

        const activeAdminCount = await prisma.user.count({

          where: {

            role: { equals: 'ADMIN' },

            isActive: true,

          },

        });

        if (activeAdminCount <= 1) {

          res.status(400).json({

            success: false,

            error: 'Cannot deactivate the last active administrator.',

          });

          return;

        }

      }

      await prisma.$transaction([

        prisma.user.update({

          where: { id: userId },

          data: {

            isActive,

            updatedAt: new Date(),

          },

        }),

        prisma.auditLog.create({

          data: {

            userId: currentAdminId,

            action: isActive ? 'USER_ACTIVATED' : 'USER_DEACTIVATED',

            details: `Administrator changed account status for user ID ${userId} (${targetUser.name}) to ${isActive ? 'Active' : 'Inactive'}.`,

          },

        }),

      ]);

      res.json({

        success: true,

        
      });

    } catch (error) {

      console.error('Update user status error:', error);

      res.status(500).json({

        success: false,

        error: 'Failed to update user status.',});

    }

  }

);
/**
 * GET /api/admin/audit-logs
 * Returns audit logs stored in the database
 */
adminRouter.get('/audit-logs', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const logs = await prisma.auditLog.findMany({
      take: 20,
      orderBy: { createdAt: 'desc' },
      include: {
        user: {
          select: {
            name: true,
            email: true,
            role: true,
          },
        },
      },
    });

    res.json({ success: true, logs });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch audit logs.' });
  }
});
/**

 * POST /api/admin/create-admin

 * Create a new administrator account

 */

adminRouter.post(

  '/create-admin',

  requireAdminAuth,

  async (req: AuthenticatedRequest, res: Response): Promise<void> => {

    try {

      const { name, email, password } = req.body;

      if (!name?.trim() || !email?.trim() || !password) {

        res.status(400).json({

          success: false,

          error: 'Name, email, and password are required.',

        });

        return;

      }

      if (password.length < 8) {

        res.status(400).json({

          success: false,

          error: 'Password must be at least 8 characters.',

        });

        return;

      }

      const normalizedEmail = email.trim().toLowerCase();

      const existingUser = await prisma.user.findUnique({

        where: { email: normalizedEmail },

      });

      if (existingUser) {

        res.status(409).json({

          success: false,

          error: 'This email is already registered.',

        });

        return;

      }

      const passwordHash = await bcrypt.hash(password, 10);

      const newAdmin = await prisma.user.create({

        data: {

          name: name.trim(),

          email: normalizedEmail,

          passwordHash,

          role: 'ADMIN',

          updatedAt: new Date(),

        },

        select: {

          id: true,

          name: true,

          email: true,

          role: true,

        },

      });

      res.status(201).json({

        success: true,

        message: 'Admin created successfully.',

        user: newAdmin,

      });

    } catch (error) {

      console.error('Create Admin Error:', error);

      res.status(500).json({

        success: false,

        error: 'Failed to create admin account.',});

    }

  }

);
/**
 * POST /api/admin/logout
 * Records logout event
 */
adminRouter.post('/logout', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (req.user?.id) {
      await prisma.auditLog.create({
        data: {
          userId: req.user.id,
          action: 'ADMIN_LOGOUT',
         details: 'Admin ${req.user.name} logged out.',
        },
      });
    }
    res.json({ success: true, message: 'Logged out successfully.' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Logout failed.' });
  }
});

