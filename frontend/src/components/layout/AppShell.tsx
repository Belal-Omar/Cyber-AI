import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Sun, Moon, Shield, LayoutDashboard, Folder, Globe, Activity, AlertTriangle, FileText, LogOut, User } from 'lucide-react'
import { cn } from '../../lib/utils'

export const AppShell = ({ children }: { children: React.ReactNode }) => {
  const location = useLocation()
  const [theme, setTheme] = useState('dark')

  useEffect(() => {
    if (document.documentElement.classList.contains('dark')) {
      setTheme('dark')
    } else {
      setTheme('light')
    }
  }, [])
  
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
          
          <div className="flex items-center gap-4">
            <button 
              onClick={() => {
                const isDark = document.documentElement.classList.toggle('dark');
                setTheme(isDark ? 'dark' : 'light');
              }}
              className="p-2 rounded-md hover:bg-surface-2 text-muted-foreground hover:text-foreground transition-colors"
              aria-label="Toggle Theme"
            >
              {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
            <div className="flex items-center px-3 py-1.5 bg-surface-2 border border-border rounded-md text-sm text-muted-foreground cursor-pointer hover:border-primary/50 transition-colors">
              <span className="mr-4">Search findings, applications...</span>
              <kbd className="px-1.5 py-0.5 bg-background rounded text-xs">⌘K</kbd>
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
