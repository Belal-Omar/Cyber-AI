import { useState, useEffect } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Folder } from 'lucide-react'
import { api, type Project } from '../lib/api'

export const Projects = () => {
  const [projects, setProjects] = useState<Project[]>([])

  useEffect(() => {
    async function load() {
      const data = await api.getProjects()
      setProjects(data)
    }
    load()
  }, [])

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Projects</h1>
          <p className="text-muted-foreground mt-1">Organize applications, scans, and audit policies into isolated project scopes.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {projects.map(proj => (
          <Card key={proj.id} className="hover:border-primary/50 transition-colors cursor-pointer">
            <CardHeader className="pb-3">
              <div className="flex justify-between items-start">
                <div className="flex items-center gap-3">
                  <Folder className="h-5 w-5 text-primary" />
                  <CardTitle>{proj.name}</CardTitle>
                </div>
                <Badge variant="outline">{proj.owner || 'Security Team'}</Badge>
              </div>
              <p className="text-sm text-muted-foreground mt-2">{proj.description}</p>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-4 gap-4 mt-4 pt-4 border-t border-border">
                <div>
                  <p className="text-xs text-muted-foreground">Apps</p>
                  <p className="font-semibold">{proj.applications_count ?? 1}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Scans</p>
                  <p className="font-semibold">{proj.assessments_count ?? 1}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Findings</p>
                  <p className="font-semibold text-destructive">{proj.findings_count ?? 0}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Score</p>
                  <p className="font-semibold text-success">{proj.posture ?? 85}/100</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
