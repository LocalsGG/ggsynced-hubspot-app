# Start.gg → HubSpot Email Sync MVP - Implementation Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Project Setup](#project-setup)
3. [Supabase Setup](#supabase-setup)
4. [HubSpot Marketplace App Setup](#hubspot-marketplace-app-setup)
5. [Start.gg OAuth Setup](#startgg-oauth-setup)
6. [Backend Implementation](#backend-implementation)
7. [Frontend Implementation](#frontend-implementation)
8. [Testing](#testing)
9. [Deployment](#deployment)
10. [Security Best Practices](#security-best-practices)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

1. **Node.js** (v18 or higher)
   - Download from: https://nodejs.org/
   - Verify installation:
     ```bash
     node --version
     npm --version
     ```

2. **Git**
   - Download from: https://git-scm.com/
   - Verify installation:
     ```bash
     git --version
     ```

3. **Code Editor**
   - Recommended: VS Code (https://code.visualstudio.com/)

4. **Account Registrations** (create these accounts before starting):
   - **Supabase**: https://supabase.com/ (free tier available)
   - **Railway**: https://railway.app/ (free tier available)
   - **HubSpot Developer Account**: https://developers.hubspot.com/
   - **Start.gg Developer Account**: https://www.start.gg/developers

---

## Project Setup

### Step 1: Create Project Directory Structure

```bash
# Create root directory
mkdir ggsynced-hubspot
cd ggsynced-hubspot

# Create backend and frontend directories
mkdir backend frontend

# Initialize git repository
git init
```

### Step 2: Create Root Files

Create `.gitignore` in the root directory:

```gitignore
# Dependencies
node_modules/
package-lock.json
yarn.lock

# Environment variables
.env
.env.local
.env.*.local

# Build outputs
dist/
build/
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
```

Create `README.md` in the root directory:

```markdown
# Start.gg → HubSpot Email Sync MVP

A HubSpot Marketplace app that syncs tournament participant emails from Start.gg to HubSpot Contacts.

## Project Structure

- `backend/` - Node.js + Express API server
- `frontend/` - React + TypeScript HubSpot embedded app
```

---

## Supabase Setup

### Step 1: Create Supabase Project

1. Go to https://supabase.com/
2. Sign up or log in
3. Click "New Project"
4. Fill in:
   - **Name**: `ggsynced-hubspot` (or your preferred name)
   - **Database Password**: Generate a strong password (save it securely)
   - **Region**: Choose closest to your deployment region
5. Click "Create new project"
6. Wait 2-3 minutes for project initialization

### Step 2: Get Supabase Credentials

1. In your Supabase project dashboard, click "Settings" (gear icon)
2. Click "API" in the left sidebar
3. Copy and save these values (you'll need them later):
   - **Project URL** (e.g., `https://xxxxx.supabase.co`)
   - **anon/public key** (starts with `eyJ...`)
   - **service_role key** (starts with `eyJ...`) - Keep this secret!

### Step 3: Create Database Tables

1. In Supabase dashboard, click "SQL Editor" in the left sidebar
2. Click "New query"
3. Paste and execute the following SQL:

```sql
-- Table for storing HubSpot OAuth tokens
CREATE TABLE hubspot_accounts (
  hub_id TEXT PRIMARY KEY,
  access_token TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Table for storing Start.gg OAuth tokens
CREATE TABLE startgg_accounts (
  startgg_user_id TEXT PRIMARY KEY,
  hub_id TEXT NOT NULL REFERENCES hubspot_accounts(hub_id) ON DELETE CASCADE,
  access_token TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for faster lookups
CREATE INDEX idx_startgg_accounts_hub_id ON startgg_accounts(hub_id);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers to auto-update updated_at
CREATE TRIGGER update_hubspot_accounts_updated_at BEFORE UPDATE ON hubspot_accounts
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_startgg_accounts_updated_at BEFORE UPDATE ON startgg_accounts
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

4. Click "Run" (or press Ctrl+Enter)
5. Verify tables were created:
   - Go to "Table Editor" in left sidebar
   - You should see `hubspot_accounts` and `startgg_accounts` tables

### Step 4: Enable Row Level Security (RLS)

1. In SQL Editor, run:

```sql
-- Enable RLS on both tables
ALTER TABLE hubspot_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE startgg_accounts ENABLE ROW LEVEL SECURITY;

-- Create policies (we'll use service_role key in backend, but this is good practice)
-- For now, we'll allow service_role to do everything via backend
-- In production, you may want more restrictive policies
```

**Note**: Since we're using the service_role key in the backend, RLS policies are less critical, but enabling RLS is a security best practice.

---

## HubSpot Marketplace App Setup

### Step 1: Create HubSpot Developer Account

1. Go to https://developers.hubspot.com/
2. Sign up or log in
3. Complete developer account setup if prompted

### Step 2: Create a New App

1. In HubSpot Developer Portal, click "Create app"
2. Fill in:
   - **App name**: `Start.gg Email Sync`
   - **Description**: `Sync tournament participant emails from Start.gg to HubSpot Contacts`
   - **App logo**: Upload a logo (optional, can be added later)
3. Click "Create app"

### Step 3: Configure OAuth Settings

1. In your app settings, click "Auth" in the left sidebar
2. Under "Redirect URLs", add:
   - `http://localhost:3000/api/auth/hubspot/callback` (for local development)
   - `https://your-railway-app.railway.app/api/auth/hubspot/callback` (for production - update after deployment)
3. Under "Scopes", select:
   - `crm.objects.contacts.read`
   - `crm.objects.contacts.write`
4. Click "Save"

### Step 4: Get OAuth Credentials

1. In the "Auth" section, you'll see:
   - **Client ID** (copy and save)
   - **Client Secret** (copy and save - keep this secret!)
2. Save these for backend environment variables

### Step 5: Configure App Settings

1. Click "App settings" in left sidebar
2. Note your **App ID** (you'll need this for the frontend)
3. Under "App URLs":
   - **App URL**: `http://localhost:3001` (for local development)
   - **App URL**: `https://your-frontend-domain.com` (for production - update after deployment)

**Note**: For local development, you'll need to use HubSpot's local development tools or ngrok for testing embedded apps.

---

## Start.gg OAuth Setup

### Step 1: Register Application

1. Go to https://www.start.gg/developers
2. Log in with your Start.gg account
3. Navigate to "Applications" or "OAuth Apps"
4. Click "Create Application" or "New App"
5. Fill in:
   - **Application Name**: `HubSpot Email Sync`
   - **Description**: `Sync tournament participant emails to HubSpot`
   - **Redirect URI**: `http://localhost:3000/api/auth/startgg/callback` (for local)
   - **Redirect URI**: `https://your-railway-app.railway.app/api/auth/startgg/callback` (for production)
6. Select scopes:
   - `user.identity`
   - `user.email`
   - `tournament.manager`
7. Submit the application

### Step 2: Get OAuth Credentials

1. After creating the app, you'll receive:
   - **Client ID** (copy and save)
   - **Client Secret** (copy and save - keep this secret!)
2. Save these for backend environment variables

### Step 3: Verify GraphQL API Access

1. Start.gg uses GraphQL API
2. Documentation: https://www.start.gg/developers/docs
3. GraphQL endpoint: `https://api.start.gg/gql/alpha`
4. You'll need to authenticate requests with the access token in the `Authorization` header

---

## Backend Implementation

### Step 1: Initialize Backend Project

```bash
cd backend
npm init -y
```

### Step 2: Install Dependencies

```bash
npm install express cors dotenv winston jsonwebtoken cookie-parser
npm install axios graphql-request graphql
npm install @supabase/supabase-js
npm install --save-dev @types/express @types/cors @types/node @types/jsonwebtoken @types/cookie-parser typescript ts-node nodemon
```

### Step 3: Configure TypeScript

Create `backend/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "moduleResolution": "node"
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

### Step 4: Update package.json Scripts

Edit `backend/package.json`:

```json
{
  "scripts": {
    "dev": "nodemon --exec ts-node src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js",
    "type-check": "tsc --noEmit"
  }
}
```

### Step 5: Create Backend Directory Structure

```bash
mkdir -p src/{config,controllers,middleware,services,types,utils}
```

### Step 6: Create Environment Configuration

Create `backend/.env.example`:

```env
# Server
PORT=3000
NODE_ENV=development
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# HubSpot OAuth
HUBSPOT_CLIENT_ID=your-hubspot-client-id
HUBSPOT_CLIENT_SECRET=your-hubspot-client-secret

# Start.gg OAuth
STARTGG_CLIENT_ID=your-startgg-client-id
STARTGG_CLIENT_SECRET=your-startgg-client-secret
STARTGG_GRAPHQL_URL=https://api.start.gg/gql/alpha

# Frontend URL (for CORS)
FRONTEND_URL=http://localhost:3001
```

Create `backend/.env` (copy from .env.example and fill in your values):

```bash
cp .env.example .env
# Then edit .env with your actual values
```

### Step 7: Create Type Definitions

Create `backend/src/types/index.ts`:

```typescript
export interface HubSpotAccount {
  hub_id: string;
  access_token: string;
  refresh_token: string;
  expires_at: Date;
}

export interface StartGGAccount {
  startgg_user_id: string;
  hub_id: string;
  access_token: string;
  refresh_token: string;
  expires_at: Date;
}

export interface Tournament {
  id: string;
  name: string;
  slug: string;
}

export interface SyncResult {
  synced: number;
  skipped: number;
  errors: number;
  errorDetails?: string[];
}

export interface JWTPayload {
  hubId: string;
  userId?: string;
}
```

### Step 8: Create Supabase Client

Create `backend/src/config/supabase.ts`:

```typescript
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('Missing Supabase environment variables');
}

export const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});
```

### Step 9: Create Logger

Create `backend/src/config/logger.ts`:

```typescript
import winston from 'winston';

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

export const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: logFormat,
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(
          ({ timestamp, level, message, ...meta }) =>
            `${timestamp} [${level}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''}`
        )
      )
    })
  ]
});
```

### Step 10: Create Token Storage Service

Create `backend/src/services/tokenStorage.ts`:

```typescript
import { supabase } from '../config/supabase';
import { HubSpotAccount, StartGGAccount } from '../types';
import { logger } from '../config/logger';

export class TokenStorageService {
  // HubSpot token operations
  async saveHubSpotAccount(account: HubSpotAccount): Promise<void> {
    try {
      const { error } = await supabase
        .from('hubspot_accounts')
        .upsert({
          hub_id: account.hub_id,
          access_token: account.access_token,
          refresh_token: account.refresh_token,
          expires_at: account.expires_at.toISOString()
        }, {
          onConflict: 'hub_id'
        });

      if (error) throw error;
      logger.info(`Saved HubSpot account for hub_id: ${account.hub_id}`);
    } catch (error) {
      logger.error('Error saving HubSpot account', { error, hub_id: account.hub_id });
      throw error;
    }
  }

  async getHubSpotAccount(hubId: string): Promise<HubSpotAccount | null> {
    try {
      const { data, error } = await supabase
        .from('hubspot_accounts')
        .select('*')
        .eq('hub_id', hubId)
        .single();

      if (error) {
        if (error.code === 'PGRST116') return null; // Not found
        throw error;
      }

      return data ? {
        hub_id: data.hub_id,
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_at: new Date(data.expires_at)
      } : null;
    } catch (error) {
      logger.error('Error getting HubSpot account', { error, hub_id: hubId });
      throw error;
    }
  }

  // Start.gg token operations
  async saveStartGGAccount(account: StartGGAccount): Promise<void> {
    try {
      const { error } = await supabase
        .from('startgg_accounts')
        .upsert({
          startgg_user_id: account.startgg_user_id,
          hub_id: account.hub_id,
          access_token: account.access_token,
          refresh_token: account.refresh_token,
          expires_at: account.expires_at.toISOString()
        }, {
          onConflict: 'startgg_user_id'
        });

      if (error) throw error;
      logger.info(`Saved Start.gg account for user_id: ${account.startgg_user_id}, hub_id: ${account.hub_id}`);
    } catch (error) {
      logger.error('Error saving Start.gg account', { error, user_id: account.startgg_user_id });
      throw error;
    }
  }

  async getStartGGAccount(hubId: string): Promise<StartGGAccount | null> {
    try {
      const { data, error } = await supabase
        .from('startgg_accounts')
        .select('*')
        .eq('hub_id', hubId)
        .single();

      if (error) {
        if (error.code === 'PGRST116') return null; // Not found
        throw error;
      }

      return data ? {
        startgg_user_id: data.startgg_user_id,
        hub_id: data.hub_id,
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_at: new Date(data.expires_at)
      } : null;
    } catch (error) {
      logger.error('Error getting Start.gg account', { error, hub_id: hubId });
      throw error;
    }
  }
}

export const tokenStorage = new TokenStorageService();
```

### Step 11: Create HubSpot Service

Create `backend/src/services/hubspot.ts`:

```typescript
import axios, { AxiosInstance } from 'axios';
import { logger } from '../config/logger';
import { TokenStorageService } from './tokenStorage';

export class HubSpotService {
  private tokenStorage: TokenStorageService;
  private baseURL = 'https://api.hubapi.com';

  constructor(tokenStorage: TokenStorageService) {
    this.tokenStorage = tokenStorage;
  }

  private async getAccessToken(hubId: string): Promise<string> {
    const account = await this.tokenStorage.getHubSpotAccount(hubId);
    if (!account) {
      throw new Error(`No HubSpot account found for hub_id: ${hubId}`);
    }

    // Check if token is expired (with 5 minute buffer)
    const now = new Date();
    const expiresAt = new Date(account.expires_at);
    const buffer = 5 * 60 * 1000; // 5 minutes in milliseconds

    if (now.getTime() >= expiresAt.getTime() - buffer) {
      logger.info(`HubSpot token expired for hub_id: ${hubId}, refreshing...`);
      return await this.refreshToken(hubId, account.refresh_token);
    }

    return account.access_token;
  }

  private async refreshToken(hubId: string, refreshToken: string): Promise<string> {
    try {
      const response = await axios.post('https://api.hubapi.com/oauth/v1/token', null, {
        params: {
          grant_type: 'refresh_token',
          client_id: process.env.HUBSPOT_CLIENT_ID,
          client_secret: process.env.HUBSPOT_CLIENT_SECRET,
          refresh_token: refreshToken
        },
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });

      const { access_token, refresh_token: new_refresh_token, expires_in } = response.data;

      // Calculate expiration time
      const expiresAt = new Date();
      expiresAt.setSeconds(expiresAt.getSeconds() + expires_in);

      // Save updated tokens
      await this.tokenStorage.saveHubSpotAccount({
        hub_id: hubId,
        access_token,
        refresh_token: new_refresh_token,
        expires_at: expiresAt
      });

      logger.info(`Refreshed HubSpot token for hub_id: ${hubId}`);
      return access_token;
    } catch (error: any) {
      logger.error('Error refreshing HubSpot token', { error: error.message, hub_id: hubId });
      throw new Error(`Failed to refresh HubSpot token: ${error.message}`);
    }
  }

  async batchUpsertContacts(hubId: string, emails: string[]): Promise<{ synced: number; errors: number; errorDetails: string[] }> {
    const accessToken = await this.getAccessToken(hubId);
    const client: AxiosInstance = axios.create({
      baseURL: this.baseURL,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });

    let synced = 0;
    let errors = 0;
    const errorDetails: string[] = [];
    const batchSize = 100;

    // Process in batches of 100
    for (let i = 0; i < emails.length; i += batchSize) {
      const batch = emails.slice(i, i + batchSize);
      
      try {
        const inputs = batch.map(email => ({
          id: email,
          properties: {
            email: email
          }
        }));

        const response = await client.post('/crm/v3/objects/contacts/batch/upsert', {
          idProperty: 'email',
          inputs
        });

        synced += response.data.results?.length || 0;
        logger.info(`Upserted batch of ${batch.length} contacts for hub_id: ${hubId}`, {
          synced: response.data.results?.length || 0
        });

        // Add delay to respect rate limits (HubSpot allows 100 requests per 10 seconds)
        if (i + batchSize < emails.length) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      } catch (error: any) {
        errors += batch.length;
        const errorMsg = error.response?.data?.message || error.message || 'Unknown error';
        errorDetails.push(`Batch ${Math.floor(i / batchSize) + 1}: ${errorMsg}`);
        logger.error('Error upserting contacts batch', {
          error: errorMsg,
          hub_id: hubId,
          batchSize: batch.length
        });
      }
    }

    return { synced, errors, errorDetails };
  }
}

export const hubspotService = new HubSpotService(tokenStorage);
```

### Step 12: Create Start.gg Service

Create `backend/src/services/startgg.ts`:

```typescript
import { GraphQLClient } from 'graphql-request';
import { logger } from '../config/logger';
import { TokenStorageService } from './tokenStorage';
import { Tournament } from '../types';

const STARTGG_GRAPHQL_URL = process.env.STARTGG_GRAPHQL_URL || 'https://api.start.gg/gql/alpha';

export class StartGGService {
  private tokenStorage: TokenStorageService;

  constructor(tokenStorage: TokenStorageService) {
    this.tokenStorage = tokenStorage;
  }

  private async getAccessToken(hubId: string): Promise<string> {
    const account = await this.tokenStorage.getStartGGAccount(hubId);
    if (!account) {
      throw new Error(`No Start.gg account found for hub_id: ${hubId}`);
    }

    // Check if token is expired (with 5 minute buffer)
    const now = new Date();
    const expiresAt = new Date(account.expires_at);
    const buffer = 5 * 60 * 1000; // 5 minutes

    if (now.getTime() >= expiresAt.getTime() - buffer) {
      logger.info(`Start.gg token expired for hub_id: ${hubId}, refreshing...`);
      return await this.refreshToken(hubId, account.refresh_token);
    }

    return account.access_token;
  }

  private async refreshToken(hubId: string, refreshToken: string): Promise<string> {
    try {
      // Start.gg token refresh endpoint (verify this in their docs)
      const response = await fetch('https://api.start.gg/oauth/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: process.env.STARTGG_CLIENT_ID!,
          client_secret: process.env.STARTGG_CLIENT_SECRET!,
          refresh_token: refreshToken
        })
      });

      if (!response.ok) {
        throw new Error(`Token refresh failed: ${response.statusText}`);
      }

      const data = await response.json();
      const { access_token, refresh_token: new_refresh_token, expires_in } = data;

      // Calculate expiration time
      const expiresAt = new Date();
      expiresAt.setSeconds(expiresAt.getSeconds() + expires_in);

      // Get existing account to preserve startgg_user_id
      const existingAccount = await this.tokenStorage.getStartGGAccount(hubId);
      if (!existingAccount) {
        throw new Error('Cannot refresh token: account not found');
      }

      // Save updated tokens
      await this.tokenStorage.saveStartGGAccount({
        startgg_user_id: existingAccount.startgg_user_id,
        hub_id: hubId,
        access_token,
        refresh_token: new_refresh_token,
        expires_at: expiresAt
      });

      logger.info(`Refreshed Start.gg token for hub_id: ${hubId}`);
      return access_token;
    } catch (error: any) {
      logger.error('Error refreshing Start.gg token', { error: error.message, hub_id: hubId });
      throw new Error(`Failed to refresh Start.gg token: ${error.message}`);
    }
  }

  async getManagedTournaments(hubId: string): Promise<Tournament[]> {
    const accessToken = await this.getAccessToken(hubId);
    const client = new GraphQLClient(STARTGG_GRAPHQL_URL, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    const query = `
      query ListManagedTournaments {
        currentUser {
          tournaments(query: {perPage: 50}) {
            nodes {
              id
              name
              slug
            }
          }
        }
      }
    `;

    try {
      const data: any = await client.request(query);
      const tournaments = data.currentUser?.tournaments?.nodes || [];
      logger.info(`Fetched ${tournaments.length} tournaments for hub_id: ${hubId}`);
      return tournaments;
    } catch (error: any) {
      logger.error('Error fetching tournaments', { error: error.message, hub_id: hubId });
      
      // Handle 403 (unauthorized) - user may have lost admin access
      if (error.response?.status === 403) {
        throw new Error('Unauthorized: You may have lost tournament manager access');
      }
      
      throw new Error(`Failed to fetch tournaments: ${error.message}`);
    }
  }

  async getParticipantEmails(hubId: string, tournamentSlug: string): Promise<string[]> {
    const accessToken = await this.getAccessToken(hubId);
    const client = new GraphQLClient(STARTGG_GRAPHQL_URL, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    const emails: string[] = [];
    let page = 1;
    let hasMorePages = true;

    const query = `
      query FetchParticipants($slug: String!, $page: Int!) {
        event(slug: $slug) {
          entrants(query: {page: $page, perPage: 100}) {
            nodes {
              participant {
                user {
                  email
                }
              }
            }
            pageInfo {
              totalPages
            }
          }
        }
      }
    `;

    try {
      while (hasMorePages) {
        const data: any = await client.request(query, {
          slug: tournamentSlug,
          page
        });

        const entrants = data.event?.entrants?.nodes || [];
        const pageInfo = data.event?.entrants?.pageInfo;

        // Extract emails (skip nulls)
        for (const entrant of entrants) {
          const email = entrant?.participant?.user?.email;
          if (email && typeof email === 'string') {
            emails.push(email);
          }
        }

        logger.info(`Fetched page ${page} for tournament ${tournamentSlug}`, {
          emailsFound: entrants.length,
          totalEmails: emails.length
        });

        hasMorePages = page < (pageInfo?.totalPages || 0);
        page++;

        // Add delay to respect rate limits
        if (hasMorePages) {
          await new Promise(resolve => setTimeout(resolve, 200));
        }
      }

      // Deduplicate emails
      const uniqueEmails = Array.from(new Set(emails));
      logger.info(`Fetched ${uniqueEmails.length} unique emails from tournament ${tournamentSlug}`);
      return uniqueEmails;
    } catch (error: any) {
      logger.error('Error fetching participant emails', {
        error: error.message,
        hub_id: hubId,
        tournamentSlug
      });

      if (error.response?.status === 403) {
        throw new Error('Unauthorized: You may have lost tournament manager access');
      }

      throw new Error(`Failed to fetch participant emails: ${error.message}`);
    }
  }
}

export const startggService = new StartGGService(tokenStorage);
```

### Step 13: Create Authentication Middleware

Create `backend/src/middleware/auth.ts`:

```typescript
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { JWTPayload } from '../types';
import { logger } from '../config/logger';

export interface AuthenticatedRequest extends Request {
  hubId?: string;
  userId?: string;
}

export const authenticate = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const token = req.cookies?.session_token;

    if (!token) {
      return res.status(401).json({ error: 'No authentication token provided' });
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      logger.error('JWT_SECRET not configured');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    const decoded = jwt.verify(token, jwtSecret) as JWTPayload;
    req.hubId = decoded.hubId;
    req.userId = decoded.userId;

    next();
  } catch (error: any) {
    logger.error('Authentication error', { error: error.message });
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};
```

### Step 14: Create Auth Controllers

Create `backend/src/controllers/authController.ts`:

```typescript
import { Request, Response } from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import { tokenStorage } from '../services/tokenStorage';
import { logger } from '../config/logger';
import { AuthenticatedRequest } from '../middleware/auth';

// HubSpot OAuth callback
export const hubspotCallback = async (req: Request, res: Response) => {
  try {
    const { code, hub_id } = req.query;

    if (!code || !hub_id) {
      return res.status(400).json({ error: 'Missing code or hub_id' });
    }

    // Exchange authorization code for tokens
    const tokenResponse = await axios.post('https://api.hubapi.com/oauth/v1/token', null, {
      params: {
        grant_type: 'authorization_code',
        client_id: process.env.HUBSPOT_CLIENT_ID,
        client_secret: process.env.HUBSPOT_CLIENT_SECRET,
        redirect_uri: process.env.HUBSPOT_REDIRECT_URI || `${process.env.BACKEND_URL}/api/auth/hubspot/callback`,
        code: code as string
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    // Calculate expiration time
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + expires_in);

    // Save tokens
    await tokenStorage.saveHubSpotAccount({
      hub_id: hub_id as string,
      access_token,
      refresh_token,
      expires_at: expiresAt
    });

    logger.info(`HubSpot OAuth completed for hub_id: ${hub_id}`);

    // Generate JWT session token
    const jwtSecret = process.env.JWT_SECRET!;
    const sessionToken = jwt.sign(
      { hubId: hub_id as string },
      jwtSecret,
      { expiresIn: '7d' }
    );

    // Set HttpOnly cookie
    res.cookie('session_token', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Redirect to frontend
    res.redirect(`${process.env.FRONTEND_URL}/?hubspot_connected=true`);
  } catch (error: any) {
    logger.error('HubSpot OAuth callback error', { error: error.message });
    res.status(500).json({ error: 'OAuth callback failed', details: error.message });
  }
};

// Start.gg OAuth callback
export const startggCallback = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { code } = req.query;
    const hubId = req.hubId;

    if (!code) {
      return res.status(400).json({ error: 'Missing authorization code' });
    }

    if (!hubId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Exchange authorization code for tokens
    const tokenResponse = await axios.post('https://api.start.gg/oauth/token', null, {
      params: {
        grant_type: 'authorization_code',
        client_id: process.env.STARTGG_CLIENT_ID,
        client_secret: process.env.STARTGG_CLIENT_SECRET,
        redirect_uri: process.env.STARTGG_REDIRECT_URI || `${process.env.BACKEND_URL}/api/auth/startgg/callback`,
        code: code as string
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    // Get user info to get startgg_user_id
    const userResponse = await axios.get('https://api.start.gg/api/user', {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });

    const startgg_user_id = userResponse.data.id?.toString() || '';

    // Calculate expiration time
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + expires_in);

    // Save tokens
    await tokenStorage.saveStartGGAccount({
      startgg_user_id,
      hub_id: hubId,
      access_token,
      refresh_token,
      expires_at: expiresAt
    });

    logger.info(`Start.gg OAuth completed for hub_id: ${hubId}, user_id: ${startgg_user_id}`);

    res.json({ success: true, message: 'Start.gg account connected' });
  } catch (error: any) {
    logger.error('Start.gg OAuth callback error', { error: error.message });
    res.status(500).json({ error: 'OAuth callback failed', details: error.message });
  }
};

// Get OAuth URLs
export const getHubSpotAuthUrl = (req: Request, res: Response) => {
  const clientId = process.env.HUBSPOT_CLIENT_ID;
  const redirectUri = process.env.HUBSPOT_REDIRECT_URI || `${process.env.BACKEND_URL}/api/auth/hubspot/callback`;
  const scopes = 'crm.objects.contacts.read crm.objects.contacts.write';

  const authUrl = `https://app.hubspot.com/oauth/authorize?client_id=${clientId}&scope=${scopes}&redirect_uri=${encodeURIComponent(redirectUri)}`;

  res.json({ authUrl });
};

export const getStartggAuthUrl = (req: Request, res: Response) => {
  const clientId = process.env.STARTGG_CLIENT_ID;
  const redirectUri = process.env.STARTGG_REDIRECT_URI || `${process.env.BACKEND_URL}/api/auth/startgg/callback`;
  const scopes = 'user.identity user.email tournament.manager';

  const authUrl = `https://www.start.gg/oauth/authorize?client_id=${clientId}&scope=${scopes}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`;

  res.json({ authUrl });
};
```

### Step 15: Create API Controllers

Create `backend/src/controllers/tournamentController.ts`:

```typescript
import { Response } from 'express';
import { startggService } from '../services/startgg';
import { AuthenticatedRequest } from '../middleware/auth';
import { logger } from '../config/logger';

export const getTournaments = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const hubId = req.hubId;
    if (!hubId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const tournaments = await startggService.getManagedTournaments(hubId);
    res.json({ tournaments });
  } catch (error: any) {
    logger.error('Error fetching tournaments', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch tournaments', details: error.message });
  }
};
```

Create `backend/src/controllers/syncController.ts`:

```typescript
import { Response } from 'express';
import { startggService } from '../services/startgg';
import { hubspotService } from '../services/hubspot';
import { AuthenticatedRequest } from '../middleware/auth';
import { logger } from '../config/logger';
import { SyncResult } from '../types';

export const syncParticipants = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const hubId = req.hubId;
    const { tournamentSlug } = req.body;

    if (!hubId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    if (!tournamentSlug) {
      return res.status(400).json({ error: 'Missing tournamentSlug' });
    }

    logger.info(`Starting sync for tournament: ${tournamentSlug}, hub_id: ${hubId}`);

    // Fetch participant emails from Start.gg
    const emails = await startggService.getParticipantEmails(hubId, tournamentSlug);
    
    if (emails.length === 0) {
      return res.json({
        synced: 0,
        skipped: 0,
        errors: 0,
        message: 'No participant emails found'
      } as SyncResult);
    }

    // Batch upsert to HubSpot
    const { synced, errors, errorDetails } = await hubspotService.batchUpsertContacts(hubId, emails);
    const skipped = emails.length - synced - errors;

    const result: SyncResult = {
      synced,
      skipped,
      errors,
      errorDetails: errorDetails.length > 0 ? errorDetails : undefined
    };

    logger.info(`Sync completed for tournament: ${tournamentSlug}`, result);
    res.json(result);
  } catch (error: any) {
    logger.error('Error syncing participants', { error: error.message });
    res.status(500).json({ error: 'Sync failed', details: error.message });
  }
};
```

### Step 16: Create Main Server File

Create `backend/src/index.ts`:

```typescript
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { logger } from './config/logger';
import { authenticate } from './middleware/auth';
import { hubspotCallback, startggCallback, getHubSpotAuthUrl, getStartggAuthUrl } from './controllers/authController';
import { getTournaments } from './controllers/tournamentController';
import { syncParticipants } from './controllers/syncController';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3001',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Auth routes
app.get('/api/auth/hubspot/url', getHubSpotAuthUrl);
app.get('/api/auth/hubspot/callback', hubspotCallback);
app.get('/api/auth/startgg/url', getStartggAuthUrl);
app.get('/api/auth/startgg/callback', startggCallback);

// Protected routes
app.get('/api/startgg/tournaments', authenticate, getTournaments);
app.post('/api/sync/startgg', authenticate, syncParticipants);

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
```

### Step 17: Test Backend Locally

1. Make sure your `.env` file is configured with all required values
2. Start the backend:

```bash
cd backend
npm run dev
```

3. Test health endpoint:

```bash
curl http://localhost:3000/health
```

Expected response:
```json
{"status":"ok","timestamp":"2024-01-01T12:00:00.000Z"}
```

---

## Frontend Implementation

### Step 1: Initialize Frontend Project

```bash
cd frontend
npx create-react-app . --template typescript
```

If create-react-app fails, use Vite instead:

```bash
npm create vite@latest . -- --template react-ts
```

### Step 2: Install Dependencies

```bash
npm install axios
npm install @hubspot/api-client
npm install --save-dev @types/node
```

### Step 3: Configure Environment Variables

Create `frontend/.env.example`:

```env
REACT_APP_BACKEND_URL=http://localhost:3000
REACT_APP_HUBSPOT_APP_ID=your-hubspot-app-id
```

Create `frontend/.env`:

```env
REACT_APP_BACKEND_URL=http://localhost:3000
REACT_APP_HUBSPOT_APP_ID=your-hubspot-app-id
```

### Step 4: Create API Client

Create `frontend/src/services/api.ts`:

```typescript
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:3000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true, // Important for cookies
  headers: {
    'Content-Type': 'application/json'
  }
});

export interface Tournament {
  id: string;
  name: string;
  slug: string;
}

export interface SyncResult {
  synced: number;
  skipped: number;
  errors: number;
  errorDetails?: string[];
  message?: string;
}

export const api = {
  getHubSpotAuthUrl: async (): Promise<string> => {
    const response = await apiClient.get('/api/auth/hubspot/url');
    return response.data.authUrl;
  },

  getStartggAuthUrl: async (): Promise<string> => {
    const response = await apiClient.get('/api/auth/startgg/url');
    return response.data.authUrl;
  },

  getTournaments: async (): Promise<Tournament[]> => {
    const response = await apiClient.get('/api/startgg/tournaments');
    return response.data.tournaments;
  },

  syncParticipants: async (tournamentSlug: string): Promise<SyncResult> => {
    const response = await apiClient.post('/api/sync/startgg', { tournamentSlug });
    return response.data;
  }
};
```

### Step 5: Create Components

Create `frontend/src/components/HubSpotConnect.tsx`:

```typescript
import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

export const HubSpotConnect: React.FC = () => {
  const [isConnecting, setIsConnecting] = useState(false);

  const handleConnect = async () => {
    try {
      setIsConnecting(true);
      const authUrl = await api.getHubSpotAuthUrl();
      window.location.href = authUrl;
    } catch (error) {
      console.error('Error getting auth URL:', error);
      alert('Failed to initiate HubSpot connection');
      setIsConnecting(false);
    }
  };

  // Check if redirected from OAuth callback
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('hubspot_connected') === 'true') {
      alert('HubSpot account connected successfully!');
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, []);

  return (
    <div style={{ padding: '20px' }}>
      <h2>Connect HubSpot</h2>
      <p>Connect your HubSpot account to sync participant emails.</p>
      <button onClick={handleConnect} disabled={isConnecting}>
        {isConnecting ? 'Connecting...' : 'Connect HubSpot'}
      </button>
    </div>
  );
};
```

Create `frontend/src/components/StartGGConnect.tsx`:

```typescript
import React, { useState } from 'react';
import { api } from '../services/api';

export const StartGGConnect: React.FC = () => {
  const [isConnecting, setIsConnecting] = useState(false);

  const handleConnect = async () => {
    try {
      setIsConnecting(true);
      const authUrl = await api.getStartggAuthUrl();
      window.location.href = authUrl;
    } catch (error) {
      console.error('Error getting auth URL:', error);
      alert('Failed to initiate Start.gg connection');
      setIsConnecting(false);
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <h2>Connect Start.gg</h2>
      <p>Connect your Start.gg account to access tournaments you manage.</p>
      <button onClick={handleConnect} disabled={isConnecting}>
        {isConnecting ? 'Connecting...' : 'Connect Start.gg'}
      </button>
    </div>
  );
};
```

Create `frontend/src/components/TournamentSelector.tsx`:

```typescript
import React, { useState, useEffect } from 'react';
import { api, Tournament } from '../services/api';

interface TournamentSelectorProps {
  onSelect: (tournamentSlug: string) => void;
}

export const TournamentSelector: React.FC<TournamentSelectorProps> = ({ onSelect }) => {
  const [tournaments, setTournaments] = useState<Tournament[]>([]);
  const [selectedSlug, setSelectedSlug] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadTournaments();
  }, []);

  const loadTournaments = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getTournaments();
      setTournaments(data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load tournaments');
      console.error('Error loading tournaments:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSelect = (slug: string) => {
    setSelectedSlug(slug);
    onSelect(slug);
  };

  if (loading) {
    return <div>Loading tournaments...</div>;
  }

  if (error) {
    return (
      <div>
        <p style={{ color: 'red' }}>Error: {error}</p>
        <button onClick={loadTournaments}>Retry</button>
      </div>
    );
  }

  if (tournaments.length === 0) {
    return <div>No tournaments found. Make sure you're a tournament manager.</div>;
  }

  return (
    <div style={{ padding: '20px' }}>
      <h2>Select Tournament</h2>
      <select
        value={selectedSlug}
        onChange={(e) => handleSelect(e.target.value)}
        style={{ width: '100%', padding: '8px', marginTop: '10px' }}
      >
        <option value="">-- Select a tournament --</option>
        {tournaments.map((tournament) => (
          <option key={tournament.id} value={tournament.slug}>
            {tournament.name}
          </option>
        ))}
      </select>
    </div>
  );
};
```

Create `frontend/src/components/SyncButton.tsx`:

```typescript
import React, { useState } from 'react';
import { api, SyncResult } from '../services/api';

interface SyncButtonProps {
  tournamentSlug: string | null;
}

export const SyncButton: React.FC<SyncButtonProps> = ({ tournamentSlug }) => {
  const [isSyncing, setIsSyncing] = useState(false);
  const [result, setResult] = useState<SyncResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSync = async () => {
    if (!tournamentSlug) {
      alert('Please select a tournament first');
      return;
    }

    try {
      setIsSyncing(true);
      setError(null);
      setResult(null);

      const syncResult = await api.syncParticipants(tournamentSlug);
      setResult(syncResult);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Sync failed');
      console.error('Error syncing:', err);
    } finally {
      setIsSyncing(false);
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <button
        onClick={handleSync}
        disabled={isSyncing || !tournamentSlug}
        style={{
          padding: '10px 20px',
          fontSize: '16px',
          backgroundColor: '#007bff',
          color: 'white',
          border: 'none',
          borderRadius: '4px',
          cursor: isSyncing || !tournamentSlug ? 'not-allowed' : 'pointer'
        }}
      >
        {isSyncing ? 'Syncing...' : 'Sync Participants'}
      </button>

      {error && (
        <div style={{ marginTop: '10px', color: 'red' }}>
          Error: {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: '20px', padding: '15px', backgroundColor: '#f0f0f0', borderRadius: '4px' }}>
          <h3>Sync Results</h3>
          <p>Synced: {result.synced}</p>
          <p>Skipped: {result.skipped}</p>
          <p>Errors: {result.errors}</p>
          {result.errorDetails && result.errorDetails.length > 0 && (
            <div>
              <strong>Error Details:</strong>
              <ul>
                {result.errorDetails.map((detail, idx) => (
                  <li key={idx}>{detail}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
```

### Step 6: Create Main App Component

Update `frontend/src/App.tsx`:

```typescript
import React, { useState } from 'react';
import './App.css';
import { HubSpotConnect } from './components/HubSpotConnect';
import { StartGGConnect } from './components/StartGGConnect';
import { TournamentSelector } from './components/TournamentSelector';
import { SyncButton } from './components/SyncButton';

function App() {
  const [selectedTournamentSlug, setSelectedTournamentSlug] = useState<string | null>(null);
  const [hubspotConnected, setHubspotConnected] = useState(false);
  const [startggConnected, setStartggConnected] = useState(false);

  return (
    <div className="App" style={{ maxWidth: '800px', margin: '0 auto', padding: '20px' }}>
      <h1>Start.gg → HubSpot Email Sync</h1>
      
      <div style={{ marginBottom: '30px' }}>
        <HubSpotConnect />
        {hubspotConnected && <p style={{ color: 'green' }}>✓ HubSpot Connected</p>}
      </div>

      <div style={{ marginBottom: '30px' }}>
        <StartGGConnect />
        {startggConnected && <p style={{ color: 'green' }}>✓ Start.gg Connected</p>}
      </div>

      {hubspotConnected && startggConnected && (
        <>
          <TournamentSelector onSelect={setSelectedTournamentSlug} />
          <SyncButton tournamentSlug={selectedTournamentSlug} />
        </>
      )}
    </div>
  );
}

export default App;
```

### Step 7: Test Frontend Locally

```bash
cd frontend
npm start
```

The app should open at `http://localhost:3001`.

---

## Testing

### Step 1: Test Backend Endpoints

Use curl or Postman to test:

```bash
# Health check
curl http://localhost:3000/health

# Get HubSpot auth URL
curl http://localhost:3000/api/auth/hubspot/url

# Get Start.gg auth URL
curl http://localhost:3000/api/auth/startgg/url
```

### Step 2: Test OAuth Flows

1. **HubSpot OAuth**:
   - Click "Connect HubSpot" in frontend
   - Complete OAuth flow
   - Verify tokens are saved in Supabase

2. **Start.gg OAuth**:
   - Click "Connect Start.gg" in frontend
   - Complete OAuth flow
   - Verify tokens are saved in Supabase

### Step 3: Test Tournament Fetching

After connecting both accounts:
- Tournament list should load
- Verify tournaments are tournaments you manage

### Step 4: Test Sync

1. Select a tournament
2. Click "Sync Participants"
3. Verify:
   - Emails are fetched from Start.gg
   - Contacts are created/updated in HubSpot
   - Sync summary is displayed

### Step 5: Test Error Handling

- Disconnect accounts and verify error messages
- Test with invalid tournament slugs
- Test token expiration scenarios

---

## Deployment

### Step 1: Prepare Backend for Deployment

1. Update `backend/.env` with production values:
   - `NODE_ENV=production`
   - `BACKEND_URL=https://your-app.railway.app`
   - `FRONTEND_URL=https://your-frontend-domain.com`
   - All production OAuth redirect URIs

2. Build backend:

```bash
cd backend
npm run build
```

### Step 2: Deploy to Railway

1. Go to https://railway.app/
2. Sign up or log in
3. Click "New Project"
4. Select "Deploy from GitHub repo" (recommended) or "Empty Project"
5. If using GitHub:
   - Connect your repository
   - Select the `backend` directory as root
6. Add environment variables in Railway dashboard:
   - All variables from your `.env` file
   - Set `NODE_ENV=production`
7. Railway will automatically detect Node.js and deploy
8. Note your Railway app URL (e.g., `https://your-app.railway.app`)

### Step 3: Update OAuth Redirect URIs

1. **HubSpot**:
   - Update redirect URI to: `https://your-app.railway.app/api/auth/hubspot/callback`

2. **Start.gg**:
   - Update redirect URI to: `https://your-app.railway.app/api/auth/startgg/callback`

### Step 4: Deploy Frontend

For HubSpot Marketplace apps, the frontend is typically embedded. You have two options:

**Option A: Deploy to Railway (for testing)**
1. Create a new Railway service for frontend
2. Set build command: `npm run build`
3. Set start command: `npx serve -s build`
4. Update `REACT_APP_BACKEND_URL` to your Railway backend URL

**Option B: Use HubSpot's App Marketplace (Production)**
1. In HubSpot Developer Portal, configure your app URL
2. HubSpot will embed your React app in an iframe
3. Your app must be accessible via HTTPS

### Step 5: Verify Deployment

1. Test health endpoint: `https://your-app.railway.app/health`
2. Test OAuth flows end-to-end
3. Verify database connections
4. Check Railway logs for errors

---

## Security Best Practices

### 1. Environment Variables

- **Never commit `.env` files to git**
- Use Railway's environment variable management
- Rotate secrets regularly

### 2. JWT Tokens

- Use strong, random `JWT_SECRET` (minimum 32 characters)
- Set appropriate expiration times
- Use HttpOnly cookies (already implemented)

### 3. OAuth Tokens

- Store tokens encrypted in Supabase (consider using Supabase Vault)
- Implement token refresh before expiration
- Handle token revocation gracefully

### 4. API Security

- Use HTTPS in production (Railway provides this)
- Validate all input
- Implement rate limiting (consider using express-rate-limit)

### 5. CORS

- Only allow your frontend domain
- Use credentials: true for cookies

### 6. Error Handling

- Don't expose sensitive information in error messages
- Log errors server-side only
- Return generic error messages to clients

### 7. Database Security

- Use service_role key only in backend
- Enable RLS on Supabase tables
- Use parameterized queries (Supabase client handles this)

---

## Troubleshooting

### Backend Issues

**Problem**: Server won't start
- Check all environment variables are set
- Verify Node.js version (v18+)
- Check port isn't already in use

**Problem**: Database connection fails
- Verify Supabase URL and service_role key
- Check network connectivity
- Verify table names match exactly

**Problem**: OAuth callbacks fail
- Verify redirect URIs match exactly in OAuth provider settings
- Check CORS settings
- Verify client ID and secret are correct

### Frontend Issues

**Problem**: API calls fail with CORS errors
- Verify `FRONTEND_URL` in backend matches frontend URL
- Check `withCredentials: true` in axios config
- Verify backend CORS settings

**Problem**: Cookies not being sent
- Verify `withCredentials: true`
- Check cookie settings (HttpOnly, Secure, SameSite)
- Test in browser DevTools → Application → Cookies

### OAuth Issues

**Problem**: "Invalid redirect_uri"
- Redirect URI must match exactly (including http/https, trailing slashes)
- Update in both OAuth provider and backend

**Problem**: Token refresh fails
- Verify refresh token endpoint URLs
- Check token expiration times
- Verify client credentials

### Sync Issues

**Problem**: No tournaments found
- Verify user has `tournament.manager` scope
- Check user is actually a tournament admin
- Verify GraphQL query syntax

**Problem**: Emails not syncing
- Check HubSpot API permissions
- Verify batch size (max 100)
- Check rate limits
- Review error logs

### Database Issues

**Problem**: Tables not found
- Run SQL migration script again
- Verify table names are lowercase
- Check Supabase project is correct

---

## Next Steps

After completing the MVP:

1. **Add Error Recovery**: Implement retry logic with exponential backoff
2. **Add Monitoring**: Set up error tracking (e.g., Sentry)
3. **Add Logging**: Enhanced logging for production debugging
4. **Add Tests**: Unit tests for services, integration tests for API
5. **Add Rate Limiting**: Protect API from abuse
6. **Add User Feedback**: Better UI/UX for sync status
7. **Add Validation**: Validate email formats before syncing
8. **Add Pagination UI**: For large tournament lists

---

## Important Notes

1. **Start.gg API**: Verify the exact GraphQL schema and endpoints in Start.gg documentation, as they may differ from examples
2. **HubSpot API**: HubSpot API versions change; verify you're using the latest Contacts API
3. **Token Refresh**: Start.gg token refresh endpoint may differ; verify in their documentation
4. **Embedded Apps**: HubSpot embedded apps have specific requirements; review HubSpot's embedded app documentation
5. **Rate Limits**: Both APIs have rate limits; implement proper retry logic in production

---

## Support Resources

- **Supabase Docs**: https://supabase.com/docs
- **Railway Docs**: https://docs.railway.app/
- **HubSpot API Docs**: https://developers.hubspot.com/docs/api/overview
- **Start.gg API Docs**: https://www.start.gg/developers/docs
- **React Docs**: https://react.dev/
- **Express Docs**: https://expressjs.com/

---

**End of Implementation Guide**

