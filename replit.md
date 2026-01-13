# Cyber Academy Pro

## Overview

Cyber Academy Pro is an interactive cybersecurity training platform that simulates hands-on security labs. Users can practice exploiting common web vulnerabilities (SQL injection, XSS, CSRF, authentication flaws, etc.) in a safe, gamified environment. The platform features user authentication, progress tracking, achievement systems, and a dark cyberpunk-themed UI.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript
- **Routing**: Wouter (lightweight alternative to React Router)
- **State Management**: TanStack React Query for server state, React hooks for local state
- **Styling**: Tailwind CSS with custom cyberpunk theme (dark mode only)
- **UI Components**: shadcn/ui component library built on Radix UI primitives
- **Animations**: Framer Motion for UI transitions
- **Build Tool**: Vite with custom plugins for Replit integration

### Backend Architecture
- **Runtime**: Node.js with Express.js
- **Language**: TypeScript (ESM modules)
- **Session Management**: express-session with MemoryStore (development) or connect-pg-simple (production)
- **API Design**: Custom typed API routes defined in `shared/routes.ts` using Zod schemas for validation

### Data Storage
- **Database**: PostgreSQL
- **ORM**: Drizzle ORM with drizzle-zod for schema-to-validation integration
- **Schema Location**: `shared/schema.ts` contains all database table definitions
- **Migrations**: Managed via `drizzle-kit push` command

### Authentication
- **Method**: Session-based authentication stored server-side
- **Password Storage**: Currently plain text (noted as needing improvement for production)
- **User Data**: Stored in PostgreSQL `users` table with JSONB fields for stats and progress

### Project Structure
```
├── client/           # Frontend React application
│   ├── src/
│   │   ├── components/   # Reusable UI components
│   │   ├── pages/        # Route page components
│   │   ├── hooks/        # Custom React hooks
│   │   ├── data/         # Static data (lab definitions)
│   │   └── lib/          # Utilities and query client
├── server/           # Backend Express application
│   ├── index.ts      # Server entry point
│   ├── routes.ts     # API route handlers
│   ├── storage.ts    # Database access layer
│   └── db.ts         # Database connection
├── shared/           # Code shared between client/server
│   ├── schema.ts     # Drizzle database schema
│   └── routes.ts     # API route type definitions
└── migrations/       # Drizzle database migrations
```

### Build System
- Development: Vite dev server with HMR, proxied through Express
- Production: Vite builds static assets, esbuild bundles server code
- Output: `dist/public` for client, `dist/index.cjs` for server

## External Dependencies

### Database
- **PostgreSQL**: Primary data store, connection via `DATABASE_URL` environment variable
- **Drizzle ORM**: Type-safe database queries and schema management

### UI Framework
- **Radix UI**: Unstyled, accessible component primitives (dialogs, dropdowns, tooltips, etc.)
- **shadcn/ui**: Pre-built component collection using Radix + Tailwind
- **Lucide React**: Icon library

### Data Visualization
- **Recharts**: Charts for user progress dashboard

### Session/Auth
- **express-session**: Server-side session management
- **memorystore**: In-memory session storage for development

### Fonts
- Google Fonts: JetBrains Mono, Share Tech Mono, Inter, DM Sans, Geist Mono, Fira Code