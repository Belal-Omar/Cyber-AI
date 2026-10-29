import { useState, useEffect } from 'react'
import { Card, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Activity, PlayCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Link } from 'react-router-dom'
import { api, type Assessment } from '../lib/api'

export const Assessments = () => {
  const [assessments, setAssessments] = useState<Assessment[]>([])

  useEffect(() => {
    async function load() {
      const data = await api.getAssessments()
      setAssessments(data)
    }
    load()
  }, [])

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Assessments & Scans</h1>
          <p className="text-muted-foreground mt-1">Monitor, execute, and verify automated security evaluations.</p>
        </div>
        <Link to="/assessments/new">
          <Button className="gap-2">
            <PlayCircle className="h-4 w-4" /> New Assessment
          </Button>
        </Link>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {assessments.map(a => (
          <Card key={a.id} className="hover:border-primary/50 transition-colors">
            <CardContent className="p-6 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="h-10 w-10 rounded-lg bg-surface-2 border border-border flex items-center justify-center">
                  <Activity className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold">{a.name}</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Target: <span className="text-foreground font-medium">{a.application}</span> • {a.type}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-8">
                <div className="w-36">
                  <div className="flex justify-between text-xs mb-1">
                    <span>Progress</span>
                    <span className="font-semibold">{a.progress}%</span>
                  </div>
                  <div className="w-full bg-surface-2 rounded-full h-2">
                    <div className="bg-primary h-2 rounded-full transition-all duration-500" style={{ width: `${a.progress}%` }}></div>
                  </div>
                </div>
                <Badge variant={a.status === 'RUNNING' ? 'warning' : a.status === 'COMPLETED' ? 'success' : 'destructive'}>
                  {a.status}
                </Badge>
                <Link to="/findings">
                  <Button variant="ghost" size="sm" className="text-xs">
                    View Findings →
                  </Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
