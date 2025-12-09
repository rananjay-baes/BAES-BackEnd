import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import twilio from 'twilio';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
// Use require for MetaAPI to avoid ESM web version
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const MetaApi = require('metaapi.cloud-sdk').default;

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
const allowedOrigins = [
  process.env.FRONTEND_URL || 'http://localhost:3000',
  process.env.ADMIN_CONSOLE_URL || 'http://localhost:3001',
  'http://localhost:3000',
  'http://localhost:3001',
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all origins for now (restrict in production)
    }
  },
  credentials: true
}));
app.use(express.json());

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('Error: Missing Supabase environment variables');
  console.error('Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_ANON_KEY) in your .env file');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Initialize Twilio client (for SMS)
const twilioAccountSid = process.env.TWILIO_ACCOUNT_SID;
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;

let twilioClient = null;
if (twilioAccountSid && twilioAuthToken) {
  twilioClient = twilio(twilioAccountSid, twilioAuthToken);
  console.log('Twilio client initialized for SMS');
} else {
  console.warn('Warning: Twilio credentials not found. SMS OTP features will not work.');
}

// Initialize SendGrid (for Email) - SendGrid is separate from Twilio
const sendGridApiKey = process.env.SENDGRID_API_KEY;
const sendGridFromEmail = process.env.SENDGRID_FROM_EMAIL || process.env.TWILIO_FROM_EMAIL || 'noreply@baessolutions.com';

if (!sendGridApiKey) {
  console.warn('Warning: SendGrid API key not found. Email OTP features will not work.');
} else {
  console.log('SendGrid configured for email');
}

// OTP Configuration
const OTP_EXPIRY_MINUTES = 10; // OTP expires in 10 minutes
const MAX_OTP_ATTEMPTS = 5; // Maximum verification attempts
const OTP_LENGTH = 6;

// Password hashing configuration
const BCRYPT_SALT_ROUNDS = 10;

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '24h'; // Token expires in 24 hours

if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.warn('⚠️  WARNING: Using default JWT_SECRET. Set JWT_SECRET environment variable in production!');
}

// MetaAPI Configuration
const METAAPI_TOKEN = process.env.METAAPI_TOKEN;
let metaApi = null;

if (METAAPI_TOKEN) {
  try {
    metaApi = new MetaApi(METAAPI_TOKEN);
    console.log('✓ MetaAPI initialized successfully');
  } catch (error) {
    console.error('⚠️  MetaAPI initialization failed:', error.message);
  }
} else {
  console.warn('⚠️  WARNING: METAAPI_TOKEN not found. MT5 metrics sync will not work.');
}

// Helper function to generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to format phone number (ensure E.164 format)
function formatPhoneNumber(phone) {
  // Remove all non-digit characters except +
  let cleaned = phone.replace(/[^\d+]/g, '');
  
  // If it doesn't start with +, add it (assuming default country code)
  if (!cleaned.startsWith('+')) {
    // You can customize this based on your default country
    cleaned = '+1' + cleaned; // Default to +1, change as needed
  }
  
  return cleaned;
}

// Helper function to hash passwords
async function hashPassword(password) {
  return await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
}

// Helper function to verify passwords (for login authentication)
async function verifyPassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

// MT5 Password Encryption Configuration
const MT5_ENCRYPTION_KEY = process.env.MT5_PASSWORD_ENCRYPTION_KEY;
const MT5_ENCRYPTION_ALGORITHM = 'aes-256-cbc';

if (!MT5_ENCRYPTION_KEY && process.env.NODE_ENV === 'production') {
  console.warn('⚠️  WARNING: MT5_PASSWORD_ENCRYPTION_KEY not set. Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
}

// Helper function to encrypt MT5 passwords (allows decryption for MetaAPI)
function encryptMT5Password(password) {
  if (!MT5_ENCRYPTION_KEY) {
    // In development, if no key is set, return password as-is with warning
    console.warn('⚠️  MT5 password not encrypted - set MT5_PASSWORD_ENCRYPTION_KEY');
    return password;
  }
  
  try {
    const iv = crypto.randomBytes(16);
    const key = Buffer.from(MT5_ENCRYPTION_KEY, 'hex');
    const cipher = crypto.createCipheriv(MT5_ENCRYPTION_ALGORITHM, key, iv);
    let encrypted = cipher.update(password, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Error encrypting MT5 password:', error);
    throw new Error('Failed to encrypt MT5 password');
  }
}

// Helper function to decrypt MT5 passwords (needed for MetaAPI connection)
function decryptMT5Password(encryptedPassword) {
  if (!MT5_ENCRYPTION_KEY) {
    // In development, if no key is set, assume password is plain text
    return encryptedPassword;
  }
  
  try {
    const parts = encryptedPassword.split(':');
    if (parts.length !== 2) {
      // Password might not be encrypted (old data or dev mode)
      return encryptedPassword;
    }
    
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const key = Buffer.from(MT5_ENCRYPTION_KEY, 'hex');
    const decipher = crypto.createDecipheriv(MT5_ENCRYPTION_ALGORITHM, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Error decrypting MT5 password:', error);
    throw new Error('Failed to decrypt MT5 password');
  }
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Please provide a valid token.'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, admin) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token. Please login again.'
      });
    }

    req.admin = admin; // Attach admin info to request
    next();
  });
}

// Middleware to check admin role
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.admin) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    if (!allowedRoles.includes(req.admin.role)) {
      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions'
      });
    }

    next();
  };
}

// Helper function to log admin actions
async function logAdminAction(adminId, adminEmail, action, resourceType, resourceId, details, req) {
  try {
    await supabase
      .from('admin_audit_logs')
      .insert([
        {
          admin_id: adminId,
          admin_email: adminEmail,
          action,
          resource_type: resourceType,
          resource_id: resourceId,
          details: details || {},
          ip_address: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
          user_agent: req.headers['user-agent']
        }
      ]);
  } catch (error) {
    console.error('Error logging admin action:', error);
    // Don't fail the request if logging fails
  }
}

// Helper function to sync MT5 metrics from MetaAPI
async function syncMT5Metrics(mt5LoginId) {
  if (!metaApi) {
    throw new Error('MetaAPI not initialized');
  }

  try {
    // Get MT5 login details
    const { data: mt5Login, error: fetchError } = await supabase
      .from('mt5_logins')
      .select('id, login, password, server, metaapi_account_id')
      .eq('id', mt5LoginId)
      .single();

    if (fetchError || !mt5Login) {
      throw new Error('MT5 login not found');
    }

    // Update status to syncing
    await supabase
      .from('mt5_logins')
      .update({ sync_status: 'syncing' })
      .eq('id', mt5LoginId);

    let account;
    let accountInfo;

    // If we already have a MetaAPI account ID, use it
    if (mt5Login.metaapi_account_id) {
      try {
        account = await metaApi.metatraderAccountApi.getAccount(mt5Login.metaapi_account_id);
      } catch (error) {
        // Account not found or invalid, we'll create a new one
        console.log('Existing MetaAPI account not found, creating new one');
      }
    }

    // Decrypt MT5 password for MetaAPI connection
    const plainMT5Password = decryptMT5Password(mt5Login.password);

    // Create or update MetaAPI account
    if (!account) {
      // Create new MetaAPI account
      const accountData = {
        name: `MT5-${mt5Login.login}`,
        type: 'cloud',
        login: mt5Login.login,
        // Note: Password should be investor (read-only) password for security
        password: plainMT5Password, // Decrypted password for MetaAPI
        server: mt5Login.server,
        platform: 'mt5',
        magic: 0
      };

      account = await metaApi.metatraderAccountApi.createAccount(accountData);
      
      // Store MetaAPI account ID
      await supabase
        .from('mt5_logins')
        .update({ metaapi_account_id: account.id })
        .eq('id', mt5LoginId);

      // Wait for account to deploy
      await account.deploy();
      await account.waitDeployed();
    }

    // Wait for connection
    const connection = account.getStreamingConnection();
    await connection.connect();
    await connection.waitSynchronized();

    // Get account information
    accountInfo = connection.accountInformation;
    const positions = connection.positions;
    const orders = connection.orders;

    // Format metrics
    const metrics = {
      balance: accountInfo.balance || 0,
      equity: accountInfo.equity || 0,
      margin: accountInfo.margin || 0,
      freeMargin: accountInfo.freeMargin || 0,
      marginLevel: accountInfo.marginLevel || 0,
      profit: accountInfo.profit || 0,
      credit: accountInfo.credit || 0,
      leverage: accountInfo.leverage || 0,
      currency: accountInfo.currency || 'USD',
      type: accountInfo.type || 'hedging',
      name: accountInfo.name || '',
      server: accountInfo.server || mt5Login.server,
      positions: positions?.length || 0,
      orders: orders?.length || 0,
      accountInfo: {
        name: accountInfo.name,
        login: mt5Login.login,
        server: mt5Login.server,
        platform: 'mt5'
      },
      lastUpdate: new Date().toISOString()
    };

    // Close connection
    await connection.close();

    // Update database with metrics
    const { error: updateError } = await supabase
      .from('mt5_logins')
      .update({
        metrics: metrics,
        metrics_last_synced: new Date().toISOString(),
        sync_status: 'success',
        updated_at: new Date().toISOString()
      })
      .eq('id', mt5LoginId);

    if (updateError) {
      throw new Error(`Failed to update metrics: ${updateError.message}`);
    }

    return { success: true, metrics };

  } catch (error) {
    console.error('Error syncing MT5 metrics:', error);

    // Update status to failed
    await supabase
      .from('mt5_logins')
      .update({ 
        sync_status: 'failed',
        updated_at: new Date().toISOString()
      })
      .eq('id', mt5LoginId);

    throw error;
  }
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running' });
});

// ============================================
// ADMIN AUTHENTICATION ENDPOINTS
// ============================================

// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }

    // Fetch admin by email
    const { data: admin, error } = await supabase
      .from('admins')
      .select('id, email, password, full_name, role, is_active')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !admin) {
      // Don't reveal whether email exists for security
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    // Check if admin is active
    if (!admin.is_active) {
      return res.status(403).json({
        success: false,
        error: 'Account is disabled. Please contact administrator.'
      });
    }

    // Verify password
    const isPasswordValid = await verifyPassword(password, admin.password);

    if (!isPasswordValid) {
      // Log failed login attempt
      await logAdminAction(
        admin.id,
        admin.email,
        'login_failed',
        'admin',
        admin.id,
        { reason: 'invalid_password' },
        req
      );

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    // Update last login time
    await supabase
      .from('admins')
      .update({ last_login_at: new Date().toISOString() })
      .eq('id', admin.id);

    // Generate JWT token
    const token = jwt.sign(
      {
        id: admin.id,
        email: admin.email,
        role: admin.role,
        fullName: admin.full_name
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    // Log successful login
    await logAdminAction(
      admin.id,
      admin.email,
      'login_success',
      'admin',
      admin.id,
      {},
      req
    );

    // Return token and admin data (excluding password)
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        admin: {
          id: admin.id,
          email: admin.email,
          fullName: admin.full_name,
          role: admin.role
        }
      }
    });

  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Verify token endpoint (for frontend to check if token is still valid)
app.get('/api/admin/verify', authenticateToken, async (req, res) => {
  try {
    // Fetch fresh admin data
    const { data: admin, error } = await supabase
      .from('admins')
      .select('id, email, full_name, role, is_active')
      .eq('id', req.admin.id)
      .single();

    if (error || !admin || !admin.is_active) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired session'
      });
    }

    res.json({
      success: true,
      data: {
        admin: {
          id: admin.id,
          email: admin.email,
          fullName: admin.full_name,
          role: admin.role
        }
      }
    });

  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Change admin password
app.post('/api/admin/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        error: 'Current password and new password are required'
      });
    }

    // Validate new password strength
    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'New password must be at least 8 characters long'
      });
    }

    // Fetch current admin data
    const { data: admin, error } = await supabase
      .from('admins')
      .select('id, email, password')
      .eq('id', req.admin.id)
      .single();

    if (error || !admin) {
      return res.status(404).json({
        success: false,
        error: 'Admin not found'
      });
    }

    // Verify current password
    const isPasswordValid = await verifyPassword(currentPassword, admin.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        error: 'Current password is incorrect'
      });
    }

    // Hash new password
    const hashedPassword = await hashPassword(newPassword);

    // Update password
    const { error: updateError } = await supabase
      .from('admins')
      .update({ password: hashedPassword, updated_at: new Date().toISOString() })
      .eq('id', admin.id);

    if (updateError) {
      console.error('Error updating password:', updateError);
      return res.status(500).json({
        success: false,
        error: 'Failed to update password'
      });
    }

    // Log password change
    await logAdminAction(
      admin.id,
      admin.email,
      'password_changed',
      'admin',
      admin.id,
      {},
      req
    );

    res.json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const {
      fullName,
      email,
      phone,
      investmentAmount,
      profitSharing,
      country,
      mt5Accounts, // Array of MT5 accounts
      emailVerified,
      phoneVerified,
      partnerId, // Optional: partner ID if user was referred by a partner
      inviteToken // Required: invitation token from signup URL
    } = req.body;

    // Validation
    if (!fullName || !email || !phone || !investmentAmount || !country) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields'
      });
    }

    // Validate invitation token (REQUIRED)
    if (!inviteToken) {
      return res.status(400).json({
        success: false,
        error: 'Invitation token is required. Please use your unique invitation link.'
      });
    }

    // Check if invitation exists and is valid
    const { data: invitation, error: inviteError } = await supabase
      .from('invites')
      .select('id, email, token, status, investment_amount, profit_sharing')
      .eq('token', inviteToken)
      .single();

    if (inviteError || !invitation) {
      return res.status(404).json({
        success: false,
        error: 'Invalid or expired invitation. Please contact support.'
      });
    }

    // Check if invitation is already used
    if (invitation.status === 'used') {
      return res.status(400).json({
        success: false,
        error: 'This invitation has already been used.'
      });
    }

    // Check if invitation status is not pending
    if (invitation.status !== 'pending') {
      return res.status(400).json({
        success: false,
        error: 'This invitation is not valid. Status: ' + invitation.status
      });
    }

    // Validate email matches invitation
    if (invitation.email.toLowerCase() !== email.toLowerCase()) {
      return res.status(400).json({
        success: false,
        error: `This invitation is for ${invitation.email}. Please use the correct email address.`
      });
    }

    // Validate MT5 accounts
    if (!mt5Accounts || !Array.isArray(mt5Accounts) || mt5Accounts.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'At least one MT5 account is required'
      });
    }

    // Validate each MT5 account
    for (const account of mt5Accounts) {
      if (!account.mt5Login || !account.mt5Password || !account.mt5Server) {
        return res.status(400).json({
          success: false,
          error: 'Each MT5 account must have login, password, and server'
        });
      }
    }

    if (!emailVerified || !phoneVerified) {
      return res.status(400).json({
        success: false,
        error: 'Email and phone must be verified'
      });
    }

    if (parseFloat(investmentAmount) < 100000) {
      return res.status(400).json({
        success: false,
        error: 'Minimum investment amount is $100,000'
      });
    }

    // Check if user already exists
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id, email')
      .eq('email', email)
      .single();

    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'User with this email already exists'
      });
    }

    // Validate partner if provided
    if (partnerId) {
      const { data: partner, error: partnerError } = await supabase
        .from('partners')
        .select('id, status')
        .eq('id', partnerId)
        .single();

      if (partnerError || !partner) {
        return res.status(400).json({
          success: false,
          error: 'Invalid partner ID'
        });
      }

      if (partner.status !== 'active') {
        return res.status(400).json({
          success: false,
          error: 'Partner is not active'
        });
      }
    }

    // Check if any MT5 login already exists for this server
    for (const account of mt5Accounts) {
      const { data: existingMT5 } = await supabase
        .from('mt5_logins')
        .select('id')
        .eq('login', account.mt5Login)
        .eq('server', account.mt5Server)
        .single();

      if (existingMT5) {
        return res.status(409).json({
          success: false,
          error: `MT5 login ${account.mt5Login} already exists for server ${account.mt5Server}`
        });
      }
    }

    // Insert user data into Supabase (without MT5 fields)
    const { data: userData, error: userError } = await supabase
      .from('users')
      .insert([
        {
          full_name: fullName,
          email: email,
          phone: phone,
          investment_amount: parseFloat(investmentAmount),
          profit_sharing: profitSharing ? parseFloat(profitSharing) : null,
          country: country,
          partner_id: partnerId || null,
          email_verified: emailVerified,
          phone_verified: phoneVerified,
          status: 'pending',
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (userError) {
      console.error('Supabase error creating user:', userError);
      return res.status(500).json({
        success: false,
        error: 'Failed to create user account',
        details: userError.message
      });
    }

    // Insert all MT5 login accounts
    const mt5InsertPromises = mt5Accounts.map(async (account, index) => {
      // Encrypt the MT5 password (not hash, so MetaAPI can decrypt and use it)
      const encryptedMT5Password = encryptMT5Password(account.mt5Password);

      return {
        user_id: userData.id,
        login: account.mt5Login,
        password: encryptedMT5Password, // Password is encrypted (not hashed) for MetaAPI
        server: account.mt5Server,
        is_active: true,
        is_primary: index === 0, // First MT5 login is primary
        created_at: new Date().toISOString()
      };
    });

    // Wait for all password encryption to complete
    const mt5DataToInsert = await Promise.all(mt5InsertPromises);

    // Insert all MT5 logins at once
    const { data: mt5Data, error: mt5Error } = await supabase
      .from('mt5_logins')
      .insert(mt5DataToInsert)
      .select();

    if (mt5Error) {
      console.error('Supabase error creating MT5 logins:', mt5Error);
      // Rollback: delete the user if MT5 insertion fails
      await supabase.from('users').delete().eq('id', userData.id);
      
      return res.status(500).json({
        success: false,
        error: 'Failed to create MT5 logins',
        details: mt5Error.message
      });
    }

    // Mark invitation as used
    const { error: inviteUpdateError } = await supabase
      .from('invites')
      .update({
        status: 'used',
        used_at: new Date().toISOString(),
        used_by_user_id: userData.id
      })
      .eq('token', inviteToken);

    if (inviteUpdateError) {
      console.error('Error updating invitation status:', inviteUpdateError);
      // Don't fail signup if invitation update fails, just log it
    }

    // Trigger metrics sync for all MT5 accounts in background (don't wait for it)
    if (metaApi && mt5Data) {
      mt5Data.forEach(mt5 => {
        syncMT5Metrics(mt5.id)
          .then(() => {
            console.log(`✓ Initial metrics synced for MT5 login ${mt5.login}`);
          })
          .catch((error) => {
            console.error(`✗ Failed to sync initial metrics for MT5 login ${mt5.login}:`, error.message);
            // Don't fail signup if metrics sync fails
          });
      });
    }

    res.status(201).json({
      success: true,
      message: 'Registration submitted successfully! Our team will contact you shortly.',
      data: {
        id: userData.id,
        email: userData.email,
        fullName: userData.full_name,
        mt5LoginCount: mt5Data.length,
        mt5LoginIds: mt5Data.map(mt5 => mt5.id)
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Email OTP endpoint
app.post('/api/send-email-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format'
      });
    }

    // Generate OTP
    const otp = generateOTP();
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + OTP_EXPIRY_MINUTES);

    // Invalidate any existing unverified OTPs for this email
    await supabase
      .from('otp_codes')
      .update({ verified: true }) // Mark as verified to invalidate
      .eq('email', email)
      .eq('type', 'email')
      .eq('verified', false);

    // Store OTP in database
    const { error: dbError } = await supabase
      .from('otp_codes')
      .insert([
        {
          email: email,
          otp_code: otp,
          type: 'email',
          expires_at: expiresAt.toISOString(),
          verified: false,
          attempts: 0
        }
      ]);

    if (dbError) {
      console.error('Database error storing OTP:', dbError);
      return res.status(500).json({
        success: false,
        error: 'Failed to generate verification code'
      });
    }

    // Send email via SendGrid
    if (sendGridApiKey) {
      try {
        const emailBody = `
          <html>
            <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
              <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #333; margin-bottom: 20px;">BAES Solutions - Email Verification</h2>
                <p style="color: #666; font-size: 16px; margin-bottom: 20px;">Your verification code is:</p>
                <div style="background-color: #f0f7ff; padding: 20px; border-radius: 6px; text-align: center; margin: 20px 0;">
                  <h1 style="color: #0066cc; font-size: 36px; letter-spacing: 8px; margin: 0; font-weight: bold;">${otp}</h1>
                </div>
                <p style="color: #666; font-size: 14px; margin-bottom: 10px;">This code will expire in ${OTP_EXPIRY_MINUTES} minutes.</p>
                <p style="color: #999; font-size: 12px; margin-top: 30px;">If you didn't request this code, please ignore this email.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                <p style="color: #999; font-size: 12px; margin: 0;">BAES Solutions LLC</p>
              </div>
            </body>
          </html>
        `;

        // SendGrid API v3
        const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${sendGridApiKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            personalizations: [{
              to: [{ email: email }]
            }],
            from: { 
              email: sendGridFromEmail,
              name: 'BAES Solutions'
            },
            subject: 'BAES Solutions - Email Verification Code',
            content: [{
              type: 'text/html',
              value: emailBody
            }]
          })
        });

        if (!response.ok) {
          const errorText = await response.text();
          let errorDetails;
          try {
            errorDetails = JSON.parse(errorText);
          } catch {
            errorDetails = errorText;
          }
          console.error('SendGrid API error:', {
            status: response.status,
            statusText: response.statusText,
            error: errorDetails
          });
          throw new Error(`SendGrid API error: ${response.status} ${response.statusText}`);
        }

        console.log(`Email OTP sent successfully to ${email}`);
      } catch (emailError) {
        console.error('Error sending email via SendGrid:', emailError);
        // In production, fail the request if email fails
        if (process.env.NODE_ENV === 'production') {
          return res.status(500).json({
            success: false,
            error: 'Failed to send verification email. Please try again later.',
            details: process.env.NODE_ENV === 'development' ? emailError.message : undefined
          });
        } else {
          // In development, log but don't fail (OTP is returned in response)
          console.warn('Email sending failed in development mode, but continuing...');
        }
      }
    } else {
      console.warn('SendGrid API key not configured. Email not sent.');
      if (process.env.NODE_ENV === 'production') {
        return res.status(500).json({
          success: false,
          error: 'Email service not configured'
        });
      }
    }

    res.json({
      success: true,
      message: 'Verification code sent to your email',
      // In development, return OTP for testing
      ...(process.env.NODE_ENV === 'development' && { otp })
    });

  } catch (error) {
    console.error('Error sending email OTP:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send verification code'
    });
  }
});

// Phone OTP endpoint
app.post('/api/send-phone-otp', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({
        success: false,
        error: 'Phone number is required'
      });
    }

    if (!twilioClient || !twilioPhoneNumber) {
      return res.status(500).json({
        success: false,
        error: 'SMS service not configured. Please contact support.'
      });
    }

    // Format phone number to E.164 format
    const formattedPhone = formatPhoneNumber(phone);

    // Generate OTP
    const otp = generateOTP();
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + OTP_EXPIRY_MINUTES);

    // Invalidate any existing unverified OTPs for this phone
    await supabase
      .from('otp_codes')
      .update({ verified: true }) // Mark as verified to invalidate
      .eq('phone', formattedPhone)
      .eq('type', 'phone')
      .eq('verified', false);

    // Store OTP in database
    const { error: dbError } = await supabase
      .from('otp_codes')
      .insert([
        {
          phone: formattedPhone,
          otp_code: otp,
          type: 'phone',
          expires_at: expiresAt.toISOString(),
          verified: false,
          attempts: 0
        }
      ]);

    if (dbError) {
      console.error('Database error storing OTP:', dbError);
      return res.status(500).json({
        success: false,
        error: 'Failed to generate verification code'
      });
    }

    // Send SMS via Twilio
    try {
      const message = await twilioClient.messages.create({
        body: `Your BAES Solutions verification code is: ${otp}. This code expires in ${OTP_EXPIRY_MINUTES} minutes.`,
        from: twilioPhoneNumber,
        to: formattedPhone
      });

      console.log(`SMS OTP sent to ${formattedPhone}, SID: ${message.sid}`);
    } catch (smsError) {
      console.error('Twilio SMS error:', smsError);
      return res.status(500).json({
        success: false,
        error: 'Failed to send SMS. Please check your phone number and try again.',
        details: smsError.message
      });
    }

    res.json({
      success: true,
      message: 'Verification code sent to your phone',
      // In development, return OTP for testing
      ...(process.env.NODE_ENV === 'development' && { otp })
    });

  } catch (error) {
    console.error('Error sending phone OTP:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send verification code'
    });
  }
});

// Verify OTP endpoint
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, phone, otp, type } = req.body;

    if (!otp || !type) {
      return res.status(400).json({
        success: false,
        error: 'OTP and type are required'
      });
    }

    if (type === 'email' && !email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required for email verification'
      });
    }

    if (type === 'phone' && !phone) {
      return res.status(400).json({
        success: false,
        error: 'Phone is required for phone verification'
      });
    }

    // Validate OTP format
    if (otp.length !== OTP_LENGTH || !/^\d+$/.test(otp)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid verification code format'
      });
    }

    // Format phone number if verifying phone
    const formattedPhone = phone ? formatPhoneNumber(phone) : null;

    // Find the OTP record
    let query = supabase
      .from('otp_codes')
      .select('*')
      .eq('type', type)
      .eq('otp_code', otp)
      .eq('verified', false)
      .gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false })
      .limit(1);

    if (type === 'email') {
      query = query.eq('email', email);
    } else {
      query = query.eq('phone', formattedPhone);
    }

    const { data: otpRecords, error: queryError } = await query;

    if (queryError) {
      console.error('Database error:', queryError);
      return res.status(500).json({
        success: false,
        error: 'Failed to verify code'
      });
    }

    if (!otpRecords || otpRecords.length === 0) {
      // Increment attempts for the most recent OTP if it exists
      let attemptQuery = supabase
        .from('otp_codes')
        .select('*')
        .eq('type', type)
        .eq('verified', false)
        .order('created_at', { ascending: false })
        .limit(1);

      if (type === 'email') {
        attemptQuery = attemptQuery.eq('email', email);
      } else {
        attemptQuery = attemptQuery.eq('phone', formattedPhone);
      }

      const { data: recentOtp } = await attemptQuery;

      if (recentOtp && recentOtp.length > 0) {
        const currentAttempts = (recentOtp[0].attempts || 0) + 1;
        await supabase
          .from('otp_codes')
          .update({ attempts: currentAttempts })
          .eq('id', recentOtp[0].id);
      }

      return res.status(400).json({
        success: false,
        error: 'Invalid or expired verification code'
      });
    }

    const otpRecord = otpRecords[0];

    // Check if max attempts exceeded
    if (otpRecord.attempts >= MAX_OTP_ATTEMPTS) {
      return res.status(400).json({
        success: false,
        error: 'Maximum verification attempts exceeded. Please request a new code.'
      });
    }

    // Mark OTP as verified
    const { error: updateError } = await supabase
      .from('otp_codes')
      .update({ verified: true })
      .eq('id', otpRecord.id);

    if (updateError) {
      console.error('Error updating OTP:', updateError);
      return res.status(500).json({
        success: false,
        error: 'Failed to verify code'
      });
    }

    res.json({
      success: true,
      message: `${type === 'email' ? 'Email' : 'Phone'} verified successfully`,
      verified: true
    });

  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to verify code'
    });
  }
});

// ============================================
// AUTHENTICATION ENDPOINTS
// ============================================

// Login endpoint (example - for when you add user authentication)
// Note: This is a template for future implementation
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }

    // Example: Fetch user by email (you'll need to add a password column to users table)
    // const { data: user, error } = await supabase
    //   .from('users')
    //   .select('id, email, password, full_name, status')
    //   .eq('email', email)
    //   .single();

    // if (error || !user) {
    //   return res.status(401).json({
    //     success: false,
    //     error: 'Invalid email or password'
    //   });
    // }

    // // Verify password using bcrypt
    // const isPasswordValid = await verifyPassword(password, user.password);

    // if (!isPasswordValid) {
    //   return res.status(401).json({
    //     success: false,
    //     error: 'Invalid email or password'
    //   });
    // }

    // // Check if user is active
    // if (user.status !== 'active') {
    //   return res.status(403).json({
    //     success: false,
    //     error: 'Account is not active. Please contact support.'
    //   });
    // }

    // // Return user data (excluding password)
    // const { password: _, ...userData } = user;
    
    // res.json({
    //   success: true,
    //   message: 'Login successful',
    //   data: userData
    // });

    return res.status(501).json({
      success: false,
      error: 'Login endpoint not yet implemented. Add password field to users table first.'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// ============================================
// PARTNER MANAGEMENT ENDPOINTS
// ============================================

// Create a new partner
app.post('/api/partners', async (req, res) => {
  try {
    const { name, email, phone, companyName, commissionRate, notes } = req.body;

    if (!name || !email) {
      return res.status(400).json({
        success: false,
        error: 'Name and email are required'
      });
    }

    // Check if partner already exists
    const { data: existingPartner } = await supabase
      .from('partners')
      .select('id')
      .eq('email', email)
      .single();

    if (existingPartner) {
      return res.status(409).json({
        success: false,
        error: 'Partner with this email already exists'
      });
    }

    const { data, error } = await supabase
      .from('partners')
      .insert([
        {
          name,
          email,
          phone: phone || null,
          company_name: companyName || null,
          commission_rate: commissionRate || 0.00,
          notes: notes || null,
          status: 'active'
        }
      ])
      .select()
      .single();

    if (error) {
      console.error('Error creating partner:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to create partner',
        details: error.message
      });
    }

    res.status(201).json({
      success: true,
      message: 'Partner created successfully',
      data
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Get all partners
app.get('/api/partners', async (req, res) => {
  try {
    const { status } = req.query;

    let query = supabase
      .from('partners')
      .select('*')
      .order('created_at', { ascending: false });

    if (status) {
      query = query.eq('status', status);
    }

    const { data, error } = await query;

    if (error) {
      console.error('Error fetching partners:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch partners'
      });
    }

    res.json({
      success: true,
      data
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Get partner statistics
app.get('/api/partners/:id/statistics', async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from('partner_statistics')
      .select('*')
      .eq('id', id)
      .single();

    if (error) {
      console.error('Error fetching partner statistics:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch partner statistics'
      });
    }

    res.json({
      success: true,
      data
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Update partner (admin)
app.put('/api/admin/partners/:partnerId', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { partnerId } = req.params;
    const { name, email, phone, companyName, commissionRate, notes, status } = req.body;

    // Check if partner exists
    const { data: existingPartner, error: checkError } = await supabase
      .from('partners')
      .select('id, email')
      .eq('id', partnerId)
      .single();

    if (checkError || !existingPartner) {
      return res.status(404).json({
        success: false,
        error: 'Partner not found'
      });
    }

    // If email is being changed, check if new email already exists
    if (email && email !== existingPartner.email) {
      const { data: emailExists } = await supabase
        .from('partners')
        .select('id')
        .eq('email', email)
        .neq('id', partnerId)
        .single();

      if (emailExists) {
        return res.status(409).json({
          success: false,
          error: 'Email already exists for another partner'
        });
      }
    }

    // Build update object
    const updateData = {
      updated_at: new Date().toISOString()
    };

    if (name !== undefined) updateData.name = name;
    if (email !== undefined) updateData.email = email;
    if (phone !== undefined) updateData.phone = phone;
    if (companyName !== undefined) updateData.company_name = companyName;
    if (commissionRate !== undefined) updateData.commission_rate = parseFloat(commissionRate);
    if (notes !== undefined) updateData.notes = notes;
    if (status !== undefined) updateData.status = status;

    // Update partner
    const { data: updatedPartner, error: updateError } = await supabase
      .from('partners')
      .update(updateData)
      .eq('id', partnerId)
      .select()
      .single();

    if (updateError) {
      console.error('Error updating partner:', updateError);
      return res.status(500).json({
        success: false,
        error: 'Failed to update partner',
        details: updateError.message
      });
    }

    res.json({
      success: true,
      message: 'Partner updated successfully',
      data: updatedPartner
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Delete partner (admin)
app.delete('/api/admin/partners/:partnerId', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { partnerId } = req.params;
    const { cascade } = req.query;

    // Check if partner exists
    const { data: existingPartner, error: checkError } = await supabase
      .from('partners')
      .select('id, name, email')
      .eq('id', partnerId)
      .single();

    if (checkError || !existingPartner) {
      return res.status(404).json({
        success: false,
        error: 'Partner not found'
      });
    }

    // Check if partner has associated users
    const { data: associatedUsers } = await supabase
      .from('users')
      .select('id')
      .eq('partner_id', partnerId);

    if (associatedUsers && associatedUsers.length > 0) {
      if (cascade === 'true') {
        // Set partner_id to null for all associated users
        await supabase
          .from('users')
          .update({ partner_id: null })
          .eq('partner_id', partnerId);
      } else {
        return res.status(400).json({
          success: false,
          error: 'Cannot delete partner with associated users. Use cascade=true to unlink users.',
          relatedData: {
            users: associatedUsers.length
          }
        });
      }
    }

    // Delete the partner
    const { error: deleteError } = await supabase
      .from('partners')
      .delete()
      .eq('id', partnerId);

    if (deleteError) {
      console.error('Error deleting partner:', deleteError);
      return res.status(500).json({
        success: false,
        error: 'Failed to delete partner',
        details: deleteError.message
      });
    }

    res.json({
      success: true,
      message: `Partner ${existingPartner.name} (${existingPartner.email}) deleted successfully`,
      deletedPartner: {
        id: existingPartner.id,
        name: existingPartner.name,
        email: existingPartner.email
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Update partner status (admin)
app.patch('/api/admin/partners/:partnerId/status', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { partnerId } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({
        success: false,
        error: 'Status is required'
      });
    }

    // Validate status
    const validStatuses = ['active', 'inactive', 'suspended'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        error: `Invalid status. Must be one of: ${validStatuses.join(', ')}`
      });
    }

    // Check if partner exists
    const { data: existingPartner, error: checkError } = await supabase
      .from('partners')
      .select('id, name, email, status')
      .eq('id', partnerId)
      .single();

    if (checkError || !existingPartner) {
      return res.status(404).json({
        success: false,
        error: 'Partner not found'
      });
    }

    // Update status
    const { data: updatedPartner, error: updateError } = await supabase
      .from('partners')
      .update({
        status,
        updated_at: new Date().toISOString()
      })
      .eq('id', partnerId)
      .select()
      .single();

    if (updateError) {
      console.error('Error updating partner status:', updateError);
      return res.status(500).json({
        success: false,
        error: 'Failed to update partner status',
        details: updateError.message
      });
    }

    res.json({
      success: true,
      message: `Partner status changed from ${existingPartner.status} to ${status}`,
      data: updatedPartner
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// ============================================
// MT5 LOGIN MANAGEMENT ENDPOINTS
// ============================================

// Get all MT5 logins for a user
app.get('/api/users/:userId/mt5-logins', async (req, res) => {
  try {
    const { userId } = req.params;

    const { data, error } = await supabase
      .from('mt5_logins')
      .select('id, login, server, is_active, is_primary, created_at, updated_at')
      .eq('user_id', userId)
      .order('is_primary', { ascending: false })
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Error fetching MT5 logins:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch MT5 logins'
      });
    }

    res.json({
      success: true,
      data
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Add a new MT5 login for a user
app.post('/api/users/:userId/mt5-logins', async (req, res) => {
  try {
    const { userId } = req.params;
    const { login, password, server, isPrimary } = req.body;

    if (!login || !password || !server) {
      return res.status(400).json({
        success: false,
        error: 'Login, password, and server are required'
      });
    }

    // Check if user exists
    const { data: user } = await supabase
      .from('users')
      .select('id')
      .eq('id', userId)
      .single();

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Check if MT5 login already exists
    const { data: existingMT5 } = await supabase
      .from('mt5_logins')
      .select('id')
      .eq('login', login)
      .eq('server', server)
      .single();

    if (existingMT5) {
      return res.status(409).json({
        success: false,
        error: 'MT5 login already exists for this server'
      });
    }

    // If setting as primary, unset other primary logins for this user
    if (isPrimary) {
      await supabase
        .from('mt5_logins')
        .update({ is_primary: false })
        .eq('user_id', userId)
        .eq('is_primary', true);
    }

    // Hash the MT5 password before storing
    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    const { data, error } = await supabase
      .from('mt5_logins')
      .insert([
        {
          user_id: userId,
          login,
          password: hashedPassword, // Password is now hashed with bcrypt
          server,
          is_active: true,
          is_primary: isPrimary || false
        }
      ])
      .select()
      .single();

    if (error) {
      console.error('Error creating MT5 login:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to create MT5 login',
        details: error.message
      });
    }

    res.status(201).json({
      success: true,
      message: 'MT5 login added successfully',
      data
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Get user with MT5 logins
app.get('/api/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    // Get user data
    const { data: user, error: userError } = await supabase
      .from('users')
      .select(`
        *,
        partners (
          id,
          name,
          email,
          company_name
        )
      `)
      .eq('id', userId)
      .single();

    if (userError || !user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Get MT5 logins
    const { data: mt5Logins } = await supabase
      .from('mt5_logins')
      .select('id, login, server, is_active, is_primary, created_at')
      .eq('user_id', userId)
      .order('is_primary', { ascending: false });

    res.json({
      success: true,
      data: {
        ...user,
        mt5_logins: mt5Logins || []
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Update MT5 login (admin)
app.put('/api/admin/mt5-logins/:mt5LoginId', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { mt5LoginId } = req.params;
    const { login, password, server, isActive, isPrimary } = req.body;

    // Check if MT5 login exists
    const { data: existingMT5, error: checkError } = await supabase
      .from('mt5_logins')
      .select('id, user_id, login, server')
      .eq('id', mt5LoginId)
      .single();

    if (checkError || !existingMT5) {
      return res.status(404).json({
        success: false,
        error: 'MT5 login not found'
      });
    }

    // If login or server is being changed, check for duplicates
    if ((login && login !== existingMT5.login) || (server && server !== existingMT5.server)) {
      const checkLogin = login || existingMT5.login;
      const checkServer = server || existingMT5.server;

      const { data: duplicate } = await supabase
        .from('mt5_logins')
        .select('id')
        .eq('login', checkLogin)
        .eq('server', checkServer)
        .neq('id', mt5LoginId)
        .single();

      if (duplicate) {
        return res.status(409).json({
          success: false,
          error: 'MT5 login already exists for this server'
        });
      }
    }

    // If setting as primary, unset other primary logins for this user
    if (isPrimary === true) {
      await supabase
        .from('mt5_logins')
        .update({ is_primary: false })
        .eq('user_id', existingMT5.user_id)
        .eq('is_primary', true)
        .neq('id', mt5LoginId);
    }

    // Build update object
    const updateData = {
      updated_at: new Date().toISOString()
    };

    if (login !== undefined) updateData.login = login;
    if (server !== undefined) updateData.server = server;
    if (isActive !== undefined) updateData.is_active = isActive;
    if (isPrimary !== undefined) updateData.is_primary = isPrimary;

    // Encrypt password if provided (not hash, so MetaAPI can use it)
    if (password !== undefined) {
      updateData.password = encryptMT5Password(password);
    }

    // Update MT5 login
    const { data: updatedMT5, error: updateError } = await supabase
      .from('mt5_logins')
      .update(updateData)
      .eq('id', mt5LoginId)
      .select('id, user_id, login, server, is_active, is_primary, created_at, updated_at')
      .single();

    if (updateError) {
      console.error('Error updating MT5 login:', updateError);
      return res.status(500).json({
        success: false,
        error: 'Failed to update MT5 login',
        details: updateError.message
      });
    }

    res.json({
      success: true,
      message: 'MT5 login updated successfully',
      data: updatedMT5
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Delete MT5 login (admin)
app.delete('/api/admin/mt5-logins/:mt5LoginId', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { mt5LoginId } = req.params;

    // Check if MT5 login exists
    const { data: existingMT5, error: checkError } = await supabase
      .from('mt5_logins')
      .select('id, user_id, login, server, is_primary')
      .eq('id', mt5LoginId)
      .single();

    if (checkError || !existingMT5) {
      return res.status(404).json({
        success: false,
        error: 'MT5 login not found'
      });
    }

    // Check if this is the only MT5 login for the user
    const { data: userMT5Logins } = await supabase
      .from('mt5_logins')
      .select('id')
      .eq('user_id', existingMT5.user_id);

    if (userMT5Logins && userMT5Logins.length === 1) {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete the only MT5 login for a user. Delete the user instead or add another MT5 login first.'
      });
    }

    // If this is a primary login, set another one as primary
    if (existingMT5.is_primary && userMT5Logins && userMT5Logins.length > 1) {
      const otherMT5 = userMT5Logins.find(mt5 => mt5.id !== mt5LoginId);
      if (otherMT5) {
        await supabase
          .from('mt5_logins')
          .update({ is_primary: true })
          .eq('id', otherMT5.id);
      }
    }

    // Delete the MT5 login
    const { error: deleteError } = await supabase
      .from('mt5_logins')
      .delete()
      .eq('id', mt5LoginId);

    if (deleteError) {
      console.error('Error deleting MT5 login:', deleteError);
      return res.status(500).json({
        success: false,
        error: 'Failed to delete MT5 login',
        details: deleteError.message
      });
    }

    res.json({
      success: true,
      message: `MT5 login ${existingMT5.login} deleted successfully`,
      deletedMT5: {
        id: existingMT5.id,
        login: existingMT5.login,
        server: existingMT5.server
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// ============================================
// MT5 METRICS SYNC ENDPOINTS
// ============================================

// Sync MT5 metrics (admin)
app.post('/api/admin/mt5-logins/:mt5LoginId/sync-metrics', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { mt5LoginId } = req.params;

    if (!metaApi) {
      return res.status(503).json({
        success: false,
        error: 'MetaAPI service not configured. Please contact administrator.'
      });
    }

    // Check if MT5 login exists
    const { data: mt5Login, error: checkError } = await supabase
      .from('mt5_logins')
      .select('id, login, server, sync_status')
      .eq('id', mt5LoginId)
      .single();

    if (checkError || !mt5Login) {
      return res.status(404).json({
        success: false,
        error: 'MT5 login not found'
      });
    }

    // Check if already syncing
    if (mt5Login.sync_status === 'syncing') {
      return res.status(409).json({
        success: false,
        error: 'Metrics sync already in progress'
      });
    }

    // Log the sync action
    if (req.admin) {
      await logAdminAction(
        req.admin.id,
        req.admin.email,
        'mt5_metrics_sync',
        'mt5_login',
        mt5LoginId,
        { login: mt5Login.login, server: mt5Login.server },
        req
      );
    }

    // Sync metrics in background
    syncMT5Metrics(mt5LoginId)
      .then((result) => {
        console.log(`✓ Metrics synced successfully for MT5 login ${mt5Login.login}`);
      })
      .catch((error) => {
        console.error(`✗ Failed to sync metrics for MT5 login ${mt5Login.login}:`, error.message);
      });

    res.json({
      success: true,
      message: 'Metrics sync started',
      data: {
        mt5LoginId,
        status: 'syncing'
      }
    });

  } catch (error) {
    console.error('Error starting metrics sync:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to start metrics sync',
      details: error.message
    });
  }
});

// Get MT5 metrics (admin)
app.get('/api/admin/mt5-logins/:mt5LoginId/metrics', authenticateToken, requireRole('admin', 'super_admin', 'viewer'), async (req, res) => {
  try {
    const { mt5LoginId } = req.params;

    const { data: mt5Login, error } = await supabase
      .from('mt5_logins')
      .select('id, login, server, metrics, metrics_last_synced, sync_status, is_active')
      .eq('id', mt5LoginId)
      .single();

    if (error || !mt5Login) {
      return res.status(404).json({
        success: false,
        error: 'MT5 login not found'
      });
    }

    res.json({
      success: true,
      data: {
        id: mt5Login.id,
        login: mt5Login.login,
        server: mt5Login.server,
        metrics: mt5Login.metrics || null,
        metricsLastSynced: mt5Login.metrics_last_synced,
        syncStatus: mt5Login.sync_status,
        isActive: mt5Login.is_active
      }
    });

  } catch (error) {
    console.error('Error fetching MT5 metrics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch metrics',
      details: error.message
    });
  }
});

// ============================================
// ADMIN API ENDPOINTS
// ============================================

// Get all users (admin)
app.get('/api/admin/users', async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50, 
      status, 
      partnerId,
      search 
    } = req.query;

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;

    let query = supabase
      .from('users')
      .select(`
        *,
        partners (
          id,
          name,
          email,
          company_name
        )
      `, { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limitNum - 1);

    // Apply filters
    if (status) {
      query = query.eq('status', status);
    }

    if (partnerId) {
      query = query.eq('partner_id', partnerId);
    }

    if (search) {
      query = query.or(`full_name.ilike.%${search}%,email.ilike.%${search}%,phone.ilike.%${search}%`);
    }

    const { data, error, count } = await query;

    if (error) {
      console.error('Error fetching users:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch users'
      });
    }

    res.json({
      success: true,
      data: data || [],
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: count || 0,
        totalPages: Math.ceil((count || 0) / limitNum)
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Get all users with MT5 accounts (admin)
app.get('/api/admin/users/with-mt5', async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;

    // Get users with their MT5 logins
    const { data: users, error: usersError, count } = await supabase
      .from('users')
      .select(`
        *,
        partners (
          id,
          name,
          email,
          company_name
        ),
        mt5_logins (
          id,
          login,
          server,
          is_active,
          is_primary,
          created_at
        )
      `, { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limitNum - 1);

    if (usersError) {
      console.error('Error fetching users with MT5:', usersError);
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch users'
      });
    }

    res.json({
      success: true,
      data: users || [],
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: count || 0,
        totalPages: Math.ceil((count || 0) / limitNum)
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Get all partners with their users (admin)
app.get('/api/admin/partners/with-users', async (req, res) => {
  try {
    const { status } = req.query;

    let query = supabase
      .from('partners')
      .select(`
        *,
        users (
          id,
          full_name,
          email,
          phone,
          investment_amount,
          country,
          status,
          created_at
        )
      `)
      .order('created_at', { ascending: false });

    if (status) {
      query = query.eq('status', status);
    }

    const { data, error } = await query;

    if (error) {
      console.error('Error fetching partners with users:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch partners'
      });
    }

    // Transform data to include user count
    const partnersWithStats = (data || []).map(partner => ({
      ...partner,
      user_count: partner.users?.length || 0,
      total_investment: partner.users?.reduce((sum, user) => sum + parseFloat(user.investment_amount || 0), 0) || 0
    }));

    res.json({
      success: true,
      data: partnersWithStats
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Get dashboard statistics (admin)
app.get('/api/admin/dashboard/stats', async (req, res) => {
  try {
    // Get total users
    const { count: totalUsers } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });

    // Get active users
    const { count: activeUsers } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true })
      .eq('status', 'active');

    // Get total partners
    const { count: totalPartners } = await supabase
      .from('partners')
      .select('*', { count: 'exact', head: true });

    // Get active partners
    const { count: activePartners } = await supabase
      .from('partners')
      .select('*', { count: 'exact', head: true })
      .eq('status', 'active');

    // Get total investment amount
    const { data: investmentData } = await supabase
      .from('users')
      .select('investment_amount');

    const totalInvestment = investmentData?.reduce(
      (sum, user) => sum + parseFloat(user.investment_amount || 0), 
      0
    ) || 0;

    // Get total MT5 accounts
    const { count: totalMT5Accounts } = await supabase
      .from('mt5_logins')
      .select('*', { count: 'exact', head: true });

    // Get recent users (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const { count: recentUsers } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true })
      .gte('created_at', sevenDaysAgo.toISOString());

    res.json({
      success: true,
      data: {
        totalUsers: totalUsers || 0,
        activeUsers: activeUsers || 0,
        pendingUsers: (totalUsers || 0) - (activeUsers || 0),
        totalPartners: totalPartners || 0,
        activePartners: activePartners || 0,
        totalInvestment,
        totalMT5Accounts: totalMT5Accounts || 0,
        recentUsers: recentUsers || 0
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Update user details (admin)
app.put('/api/admin/users/:userId', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { userId } = req.params;
    const {
      fullName,
      email,
      phone,
      investmentAmount,
      profitSharing,
      country,
      status,
      partnerId
    } = req.body;

    // Check if user exists
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id, email')
      .eq('id', userId)
      .single();

    if (checkError || !existingUser) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // If email is being changed, check if new email already exists
    if (email && email !== existingUser.email) {
      const { data: emailExists } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .neq('id', userId)
        .single();

      if (emailExists) {
        return res.status(409).json({
          success: false,
          error: 'Email already exists for another user'
        });
      }
    }

    // Validate partner if provided
    if (partnerId !== undefined && partnerId !== null) {
      const { data: partner, error: partnerError } = await supabase
        .from('partners')
        .select('id, status')
        .eq('id', partnerId)
        .single();

      if (partnerError || !partner) {
        return res.status(400).json({
          success: false,
          error: 'Invalid partner ID'
        });
      }

      if (partner.status !== 'active') {
        return res.status(400).json({
          success: false,
          error: 'Partner is not active'
        });
      }
    }

    // Build update object (only include provided fields)
    const updateData = {
      updated_at: new Date().toISOString()
    };

    if (fullName !== undefined) updateData.full_name = fullName;
    if (email !== undefined) updateData.email = email;
    if (phone !== undefined) updateData.phone = phone;
    if (investmentAmount !== undefined) updateData.investment_amount = parseFloat(investmentAmount);
    if (profitSharing !== undefined) updateData.profit_sharing = profitSharing ? parseFloat(profitSharing) : null;
    if (country !== undefined) updateData.country = country;
    if (status !== undefined) updateData.status = status;
    if (partnerId !== undefined) updateData.partner_id = partnerId;

    // Update user
    const { data: updatedUser, error: updateError } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', userId)
      .select(`
        *,
        partners (
          id,
          name,
          email,
          company_name
        )
      `)
      .single();

    if (updateError) {
      console.error('Error updating user:', updateError);
      return res.status(500).json({
        success: false,
        error: 'Failed to update user',
        details: updateError.message
      });
    }

    res.json({
      success: true,
      message: 'User updated successfully',
      data: updatedUser
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Delete user (admin)
app.delete('/api/admin/users/:userId', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { cascade } = req.query; // Option to cascade delete related data

    // Check if user exists
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id, full_name, email')
      .eq('id', userId)
      .single();

    if (checkError || !existingUser) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // If cascade is true, delete related MT5 logins first
    if (cascade === 'true') {
      // Delete MT5 logins
      const { error: mt5DeleteError } = await supabase
        .from('mt5_logins')
        .delete()
        .eq('user_id', userId);

      if (mt5DeleteError) {
        console.error('Error deleting MT5 logins:', mt5DeleteError);
        return res.status(500).json({
          success: false,
          error: 'Failed to delete user MT5 logins',
          details: mt5DeleteError.message
        });
      }

      // Delete invites associated with this user (by email and by used_by_user_id)
      await supabase
        .from('invites')
        .delete()
        .eq('email', existingUser.email);
      
      await supabase
        .from('invites')
        .delete()
        .eq('used_by_user_id', userId);
    } else {
      // Check if user has MT5 logins
      const { data: mt5Logins } = await supabase
        .from('mt5_logins')
        .select('id')
        .eq('user_id', userId);

      if (mt5Logins && mt5Logins.length > 0) {
        return res.status(400).json({
          success: false,
          error: 'Cannot delete user with existing MT5 logins. Use cascade=true to delete all related data.',
          relatedData: {
            mt5Logins: mt5Logins.length
          }
        });
      }
    }

    // Delete the user
    const { error: deleteError } = await supabase
      .from('users')
      .delete()
      .eq('id', userId);

    if (deleteError) {
      console.error('Error deleting user:', deleteError);
      return res.status(500).json({
        success: false,
        error: 'Failed to delete user',
        details: deleteError.message
      });
    }

    res.json({
      success: true,
      message: `User ${existingUser.full_name} (${existingUser.email}) deleted successfully`,
      deletedUser: {
        id: existingUser.id,
        fullName: existingUser.full_name,
        email: existingUser.email
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Update user status (admin - quick status change)
app.patch('/api/admin/users/:userId/status', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({
        success: false,
        error: 'Status is required'
      });
    }

    // Validate status
    const validStatuses = ['pending', 'active', 'suspended', 'rejected'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        error: `Invalid status. Must be one of: ${validStatuses.join(', ')}`
      });
    }

    // Check if user exists
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id, full_name, email, status')
      .eq('id', userId)
      .single();

    if (checkError || !existingUser) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Update status
    const { data: updatedUser, error: updateError } = await supabase
      .from('users')
      .update({
        status,
        updated_at: new Date().toISOString()
      })
      .eq('id', userId)
      .select()
      .single();

    if (updateError) {
      console.error('Error updating user status:', updateError);
      return res.status(500).json({
        success: false,
        error: 'Failed to update user status',
        details: updateError.message
      });
    }

    res.json({
      success: true,
      message: `User status changed from ${existingUser.status} to ${status}`,
      data: updatedUser
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// ============================================
// INVITE MANAGEMENT ENDPOINTS
// ============================================

// Generate unique token for invite
function generateInviteToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Create invite and send email
app.post('/api/admin/invites', async (req, res) => {
  try {
    const { email, investmentAmount, profitSharing } = req.body;

    if (!email || !investmentAmount || profitSharing === undefined) {
      return res.status(400).json({
        success: false,
        error: 'Email, investment amount, and profit sharing are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format'
      });
    }

    // Validate profit sharing (0-100)
    const profitSharingNum = parseFloat(profitSharing);
    if (isNaN(profitSharingNum) || profitSharingNum < 0 || profitSharingNum > 100) {
      return res.status(400).json({
        success: false,
        error: 'Profit sharing must be between 0 and 100'
      });
    }

    // Generate unique token
    const token = generateInviteToken();
    
    // Get frontend URL for invite links (use production URL for invites)
    const inviteFrontendUrl = process.env.INVITE_FRONTEND_URL || process.env.FRONTEND_URL || 'https://baessolutions.com';
    const inviteLink = `${inviteFrontendUrl}/signup?invite=${token}&profitSharing=${profitSharingNum}`;

    // Create invite in database
    const { data: invite, error: inviteError } = await supabase
      .from('invites')
      .insert([
        {
          email,
          investment_amount: parseFloat(investmentAmount),
          profit_sharing: profitSharingNum,
          token,
          status: 'pending',
          expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
          created_by: req.headers['x-admin-email'] || 'admin'
        }
      ])
      .select()
      .single();

    if (inviteError) {
      console.error('Error creating invite:', inviteError);
      return res.status(500).json({
        success: false,
        error: 'Failed to create invite',
        details: inviteError.message
      });
    }

    // Send email with invite link
    let emailSent = false;
    let emailError = null;

    if (sendGridApiKey) {
      try {
        console.log(`Attempting to send invite email to ${email}...`);
        const emailBody = `
          <html>
            <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
              <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px;">
                <h2 style="color: #333; margin-bottom: 20px;">Welcome to BAES Solutions</h2>
                <p style="color: #666; line-height: 1.6;">
                  You have been invited to join BAES Solutions. Please use the link below to complete your registration.
                </p>
                <div style="background-color: #f9f9f9; padding: 20px; border-radius: 4px; margin: 20px 0;">
                  <p style="margin: 5px 0; color: #333;"><strong>Investment Amount:</strong> $${parseFloat(investmentAmount).toLocaleString()}</p>
                  <p style="margin: 5px 0; color: #333;"><strong>Profit Sharing:</strong> ${profitSharingNum}%</p>
                </div>
                <div style="text-align: center; margin: 30px 0;">
                  <a href="${inviteLink}" 
                     style="display: inline-block; background-color: #0066cc; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                    Complete Registration
                  </a>
                </div>
                <p style="color: #999; font-size: 12px; margin-top: 30px;">
                  This invite link will expire in 30 days. If you didn't request this invitation, please ignore this email.
                </p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                <p style="color: #666; font-size: 12px;">BAES Solutions LLC</p>
              </div>
            </body>
          </html>
        `;

        const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sendGridApiKey}`,
          },
          body: JSON.stringify({
            personalizations: [
              {
                to: [{ email }],
                subject: 'Invitation to Join BAES Solutions',
              },
            ],
            from: {
              email: sendGridFromEmail,
            },
            content: [
              {
                type: 'text/html',
                value: emailBody,
              },
            ],
          }),
        });

        if (!response.ok) {
          const errorText = await response.text();
          console.error('SendGrid API error:', {
            status: response.status,
            statusText: response.statusText,
            body: errorText,
            email: email,
            fromEmail: sendGridFromEmail,
          });
          emailError = `SendGrid API error: ${response.status} ${response.statusText} - ${errorText}`;
          throw new Error(emailError);
        }

        emailSent = true;
        console.log(`✓ Invite email successfully sent to ${email}`);
      } catch (emailError) {
        console.error('Error sending invite email via SendGrid:', {
          error: emailError.message,
          stack: emailError.stack,
          email: email,
          sendGridConfigured: !!sendGridApiKey,
          fromEmail: sendGridFromEmail,
        });
        emailError = emailError.message || 'Unknown error sending email';
      }
    } else {
      console.warn('SendGrid API key not configured. Invite email not sent.');
      emailError = 'SendGrid API key not configured';
    }

    // Return response with email status
    res.status(201).json({
      success: true,
      message: emailSent 
        ? 'Invite created and email sent successfully' 
        : 'Invite created successfully, but email could not be sent',
      data: {
        invite,
        inviteLink,
        emailSent,
        emailError: emailError || null,
      },
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message,
    });
  }
});

// Get invite by token (for frontend to validate)
app.get('/api/invites/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const { data: invite, error } = await supabase
      .from('invites')
      .select('*')
      .eq('token', token)
      .single();

    if (error || !invite) {
      return res.status(404).json({
        success: false,
        error: 'Invite not found or invalid',
      });
    }

    if (new Date(invite.expires_at) < new Date()) {
      return res.status(400).json({
        success: false,
        error: 'Invite has expired',
      });
    }

    if (invite.status === 'used') {
      return res.status(400).json({
        success: false,
        error: 'Invite has already been used',
      });
    }

    res.json({
      success: true,
      data: {
        email: invite.email,
        investmentAmount: invite.investment_amount,
        profitSharing: invite.profit_sharing,
      },
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

// Get all invites (admin)
app.get('/api/admin/invites', async (req, res) => {
  try {
    const { status, page = 1, limit = 50 } = req.query;

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;

    let query = supabase
      .from('invites')
      .select(`
        *,
        users (
          id,
          full_name,
          email
        )
      `, { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limitNum - 1);

    if (status) {
      query = query.eq('status', status);
    }

    const { data, error, count } = await query;

    if (error) {
      console.error('Error fetching invites:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch invites'
      });
    }

    res.json({
      success: true,
      data: data || [],
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: count || 0,
        totalPages: Math.ceil((count || 0) / limitNum)
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Delete invite (admin)
app.delete('/api/admin/invites/:inviteId', authenticateToken, requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const { inviteId } = req.params;

    // Check if invite exists
    const { data: existingInvite, error: checkError } = await supabase
      .from('invites')
      .select('id, email, status, token')
      .eq('id', inviteId)
      .single();

    if (checkError || !existingInvite) {
      return res.status(404).json({
        success: false,
        error: 'Invite not found'
      });
    }

    // Check if invite is already used
    if (existingInvite.status === 'used') {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete an invite that has already been used. Delete the user instead.',
        invite: {
          id: existingInvite.id,
          email: existingInvite.email,
          status: existingInvite.status
        }
      });
    }

    // Delete the invite
    const { error: deleteError } = await supabase
      .from('invites')
      .delete()
      .eq('id', inviteId);

    if (deleteError) {
      console.error('Error deleting invite:', deleteError);
      return res.status(500).json({
        success: false,
        error: 'Failed to delete invite',
        details: deleteError.message
      });
    }

    // Log the action
    if (req.admin) {
      await logAdminAction(
        req.admin.id,
        req.admin.email,
        'invite_delete',
        'invite',
        inviteId,
        { email: existingInvite.email, status: existingInvite.status },
        req
      );
    }

    res.json({
      success: true,
      message: `Invite for ${existingInvite.email} deleted successfully`,
      deletedInvite: {
        id: existingInvite.id,
        email: existingInvite.email,
        status: existingInvite.status
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Mark invite as used when user signs up
app.post('/api/invites/:token/use', async (req, res) => {
  try {
    const { token } = req.params;
    const { userId } = req.body;

    const { data: invite, error: fetchError } = await supabase
      .from('invites')
      .select('*')
      .eq('token', token)
      .single();

    if (fetchError || !invite) {
      return res.status(404).json({
        success: false,
        error: 'Invite not found',
      });
    }

    if (invite.status === 'used') {
      return res.status(400).json({
        success: false,
        error: 'Invite has already been used',
      });
    }

    const { error: updateError } = await supabase
      .from('invites')
      .update({
        status: 'used',
        used_at: new Date().toISOString(),
        used_by_user_id: userId || null,
      })
      .eq('token', token);

    if (updateError) {
      console.error('Error updating invite:', updateError);
      return res.status(500).json({
        success: false,
        error: 'Failed to mark invite as used',
      });
    }

    res.json({
      success: true,
      message: 'Invite marked as used',
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  if (process.env.NODE_ENV === 'production') {
    console.log('Production server started successfully');
  }
});

