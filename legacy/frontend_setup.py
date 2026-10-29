import os
from pathlib import Path

src = Path("frontend/src")
(src / "lib").mkdir(parents=True, exist_ok=True)
(src / "components" / "ui").mkdir(parents=True, exist_ok=True)
(src / "components" / "layout").mkdir(parents=True, exist_ok=True)
(src / "mock").mkdir(parents=True, exist_ok=True)
(src / "pages").mkdir(parents=True, exist_ok=True)

# 1. lib/utils.ts
with open(src / "lib" / "utils.ts", "w") as f:
    f.write('''import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
''')

# 2. components/ui/button.tsx
with open(src / "components" / "ui" / "button.tsx", "w") as f:
    f.write('''import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "../../lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary/90",
        destructive: "bg-destructive text-destructive-foreground hover:bg-destructive/90",
        outline: "border border-input bg-background hover:bg-accent hover:text-accent-foreground",
        secondary: "bg-secondary text-secondary-foreground hover:bg-secondary/80",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-9 rounded-md px-3",
        lg: "h-11 rounded-md px-8",
        icon: "h-10 w-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props} />
    )
  }
)
Button.displayName = "Button"
export { Button, buttonVariants }
''')

# 3. components/ui/card.tsx
with open(src / "components" / "ui" / "card.tsx", "w") as f:
    f.write('''import * as React from "react"
import { cn } from "../../lib/utils"

const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(({ className, ...props }, ref) => (
  <div ref={ref} className={cn("rounded-xl border bg-card text-card-foreground shadow-sm", className)} {...props} />
))
Card.displayName = "Card"

const CardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(({ className, ...props }, ref) => (
  <div ref={ref} className={cn("flex flex-col space-y-1.5 p-6", className)} {...props} />
))
CardHeader.displayName = "CardHeader"

const CardTitle = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLHeadingElement>>(({ className, ...props }, ref) => (
  <h3 ref={ref} className={cn("font-semibold leading-none tracking-tight", className)} {...props} />
))
CardTitle.displayName = "CardTitle"

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(({ className, ...props }, ref) => (
  <div ref={ref} className={cn("p-6 pt-0", className)} {...props} />
))
CardContent.displayName = "CardContent"

export { Card, CardHeader, CardTitle, CardContent }
''')

# 4. components/ui/badge.tsx
with open(src / "components" / "ui" / "badge.tsx", "w") as f:
    f.write('''import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "../../lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground hover:bg-primary/80",
        secondary: "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        destructive: "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80",
        outline: "text-foreground",
        success: "border-transparent bg-success text-success-foreground hover:bg-success/80",
        warning: "border-transparent bg-warning text-warning-foreground hover:bg-warning/80",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
''')

# 5. mock/data.ts
with open(src / "mock" / "data.ts", "w") as f:
    f.write('''export const mockApplications = [
  { id: '1', name: 'Digital Store', environment: 'Production', baseUrl: 'https://store.example.com', score: 82, endpoints: 42, openFindings: 3 },
  { id: '2', name: 'Secure Document Vault', environment: 'Staging', baseUrl: 'https://vault.staging.example.com', score: 95, endpoints: 18, openFindings: 0 },
  { id: '3', name: 'Payment API', environment: 'Production', baseUrl: 'https://api.example.com', score: 64, endpoints: 120, openFindings: 12 },
];

export const mockFindings = [
  { id: 'f1', title: 'Broken Object Level Authorization', severity: 'HIGH', confidence: 94, status: 'OPEN', application: 'Digital Store', endpoint: 'GET /api/users/{id}', detected: '2026-09-22T01:14:00Z' },
  { id: 'f2', title: 'Stored Cross-Site Scripting', severity: 'CRITICAL', confidence: 88, status: 'OPEN', application: 'Payment API', endpoint: 'POST /api/comments', detected: '2026-09-21T14:22:00Z' },
  { id: 'f3', title: 'Missing Security Headers', severity: 'LOW', confidence: 100, status: 'OPEN', application: 'Secure Document Vault', endpoint: 'GET /', detected: '2026-09-20T09:00:00Z' },
];
''')

# 6. components/layout/AppShell.tsx
with open(src / "components" / "layout" / "AppShell.tsx", "w") as f:
    f.write('''import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, Folder, Globe, Activity, AlertTriangle, FileText, Settings, LogOut, User } from 'lucide-react'
import { cn } from '../../lib/utils'

export const AppShell = ({ children }: { children: React.ReactNode }) => {
  const location = useLocation()
  
  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Projects', path: '/projects', icon: Folder },
    { name: 'Applications', path: '/applications', icon: Globe },
    { name: 'Assessments', path: '/assessments', icon: Activity },
    { name: 'Findings', path: '/findings', icon: AlertTriangle },
    { name: 'Reports', path: '/reports', icon: FileText },
  ]

  return (
    <div className="flex h-screen bg-background text-foreground dark">
      {/* Sidebar */}
      <div className="w-64 bg-surface-1 border-r border-border flex flex-col">
        <div className="h-16 flex items-center px-6 border-b border-border">
          <Shield className="w-6 h-6 text-primary mr-2" />
          <span className="font-bold text-lg tracking-tight">CyberAI</span>
        </div>
        <div className="flex-1 py-4 overflow-y-auto">
          <nav className="px-3 space-y-1">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path
              const Icon = item.icon
              return (
                <Link
                  key={item.name}
                  to={item.path}
                  className={cn(
                    "flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors",
                    isActive ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                  )}
                >
                  <Icon className={cn("mr-3 h-5 w-5", isActive ? "text-primary" : "text-muted-foreground")} />
                  {item.name}
                </Link>
              )
            })}
          </nav>
        </div>
        <div className="p-4 border-t border-border">
          <div className="flex items-center">
            <div className="w-8 h-8 rounded-full bg-secondary flex items-center justify-center mr-3">
              <User className="w-4 h-4 text-secondary-foreground" />
            </div>
            <div className="flex-1">
              <p className="text-sm font-medium">Belal</p>
              <p className="text-xs text-muted-foreground">Security Engineer</p>
            </div>
            <LogOut className="w-4 h-4 text-muted-foreground hover:text-foreground cursor-pointer" />
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* TopNav */}
        <header className="h-16 bg-surface-1 border-b border-border flex items-center justify-between px-6">
          <div className="flex items-center text-sm text-muted-foreground">
            <span className="flex items-center px-2 py-1 rounded bg-secondary/50 border border-border mr-3">
              <span className="w-2 h-2 rounded-full bg-success mr-2"></span>
              Environment: Authorized
            </span>
          </div>
          <div className="flex items-center">
            <div className="flex items-center px-3 py-1.5 bg-surface-2 border border-border rounded-md text-sm text-muted-foreground cursor-pointer hover:border-primary/50 transition-colors">
              <span className="mr-4">Search findings, applications...</span>
              <kbd className="px-1.5 py-0.5 bg-background rounded text-xs">âŒ˜K</kbd>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto bg-background p-8">
          {children}
        </main>
      </div>
    </div>
  )
}
''')

# 7. pages/Dashboard.tsx
with open(src / "pages" / "Dashboard.tsx", "w") as f:
    f.write('''import React from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Shield, Activity, Globe, AlertTriangle, Zap } from 'lucide-react'
import { mockFindings, mockApplications } from '../mock/data'

export const Dashboard = () => {
  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Good morning, Belal</h1>
        <p className="text-muted-foreground mt-1">Here is your application security overview.</p>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Applications</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockApplications.length}</div>
            <p className="text-xs text-muted-foreground">+1 from last week</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Assessments</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">2</div>
            <p className="text-xs text-muted-foreground">In progress</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Open Findings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockFindings.length}</div>
            <p className="text-xs text-muted-foreground">Across all scopes</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Posture</CardTitle>
            <Shield className="h-4 w-4 text-success" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-success">82/100</div>
            <p className="text-xs text-muted-foreground">Average score</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Recent Findings */}
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Recent Findings</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {mockFindings.map(finding => (
                <div key={finding.id} className="flex items-center justify-between border-b border-border pb-4 last:border-0 last:pb-0">
                  <div>
                    <div className="flex items-center">
                      <Badge variant={finding.severity === 'CRITICAL' ? 'destructive' : finding.severity === 'HIGH' ? 'destructive' : finding.severity === 'MEDIUM' ? 'warning' : 'secondary'} className="mr-2">
                        {finding.severity}
                      </Badge>
                      <span className="font-medium text-sm">{finding.title}</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {finding.application} â€¢ {finding.endpoint}
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {new Date(finding.detected).toLocaleDateString()}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* AI Insight */}
        <Card className="border-ai/30 bg-ai/5">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center text-sm font-medium text-ai">
              <Zap className="w-4 h-4 mr-2" />
              AI Security Insight
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-relaxed mb-4">
              3 findings appear to be related to missing object-level authorization checks across the Payment API.
            </p>
            <div className="text-xs space-y-2">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Confidence:</span>
                <span className="font-medium text-foreground">High (92%)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Action:</span>
                <span className="font-medium text-primary hover:underline cursor-pointer">Review IAM policies</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
''')

# 8. main.tsx
with open(src / "main.tsx", "w") as f:
    f.write('''import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import './index.css'
import { AppShell } from './components/layout/AppShell'
import { Dashboard } from './pages/Dashboard'

const queryClient = new QueryClient()

const App = () => {
  return (
    <div className="dark">
      <AppShell>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/login" element={<div>Login (WIP)</div>} />
          <Route path="/projects" element={<div>Projects (WIP)</div>} />
          <Route path="/applications" element={<div>Applications (WIP)</div>} />
          <Route path="/assessments" element={<div>Assessments (WIP)</div>} />
          <Route path="/findings" element={<div>Findings (WIP)</div>} />
          <Route path="/reports" element={<div>Reports (WIP)</div>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </div>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
''')

print("Frontend setup script completed successfully.")
