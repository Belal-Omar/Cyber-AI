import { useState, useEffect } from 'react'
import { Card, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Globe, Server, Plus, PlayCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import { api, type Application } from '../lib/api'
import { Button } from '../components/ui/button'

export const Applications = () => {
  const [apps, setApps] = useState<Application[]>([])

  useEffect(() => {
    async function load() {
      const data = await api.getApplications()
      setApps(data)
    }
    load()
  }, [])

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Applications</h1>
          <p className="text-muted-foreground mt-1">Manage your authorized security targets and scopes.</p>
        </div>
        <Link to="/assessments/new">
          <Button className="gap-2">
            <Plus className="h-4 w-4" /> Add Target Scope
          </Button>
        </Link>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {apps.map(app => (
          <Card key={app.id} className="hover:border-primary/50 transition-colors">
            <CardContent className="p-6 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="h-12 w-12 rounded-lg bg-surface-2 border border-border flex items-center justify-center">
                  <Globe className="h-6 w-6 text-primary" />
                </div>
                <div>
                  <Link to={`/applications/${app.id}`} className="text-lg font-semibold hover:text-primary hover:underline">
                    {app.name}
                  </Link>
                  <div className="flex items-center gap-3 text-sm text-muted-foreground mt-1">
                    <span className="flex items-center gap-1">
                      <Server className="h-3 w-3"/> {app.environment}
                    </span>
                    <span>•</span>
                    <a href={app.baseUrl} target="_blank" rel="noreferrer" className="hover:text-primary hover:underline">
                      {app.baseUrl}
                    </a>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-8">
                <div className="text-center">
                  <p className="text-sm text-muted-foreground mb-1">Score</p>
                  <span className="font-bold text-success">{app.score}/100</span>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground mb-1">Endpoints</p>
                  <span className="font-bold">{app.endpoints || 1}</span>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground mb-1">Findings</p>
                  <Badge variant={app.openFindings > 0 ? "destructive" : "success"}>
                    {app.openFindings}
                  </Badge>
                </div>
                <div>
                  <Link to={`/assessments/new`}>
                    <Button variant="outline" size="sm" className="gap-1">
                      <PlayCircle className="h-3.5 w-3.5" /> Scan
                    </Button>
                  </Link>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
