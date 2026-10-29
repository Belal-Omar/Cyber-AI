import { useState, useEffect } from 'react'
import { Card, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Link } from 'react-router-dom'
import { api, type Finding } from '../lib/api'

export const Findings = () => {
  const [findings, setFindings] = useState<Finding[]>([])
  const [filter, setFilter] = useState<string>('ALL')

  useEffect(() => {
    async function load() {
      const data = await api.getFindings()
      setFindings(data)
    }
    load()
  }, [])

  const filtered = filter === 'ALL' 
    ? findings 
    : findings.filter(f => filter === 'OPEN' ? f.status === 'OPEN' : f.severity === filter)

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Findings</h1>
          <p className="text-muted-foreground mt-1">Live detected vulnerabilities, evidence context, and remediation guidance.</p>
        </div>
        <div className="flex gap-2">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(lvl => (
            <button
              key={lvl}
              onClick={() => setFilter(lvl)}
              className={`text-xs px-3 py-1.5 rounded-md font-medium border transition-colors ${
                filter === lvl 
                  ? 'bg-primary text-primary-foreground border-primary' 
                  : 'bg-surface-2 text-muted-foreground border-border hover:bg-surface-3'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <table className="w-full text-sm text-left">
            <thead className="bg-surface-2 text-muted-foreground border-b border-border">
              <tr>
                <th className="px-6 py-4 font-medium">Severity</th>
                <th className="px-6 py-4 font-medium">Finding Title</th>
                <th className="px-6 py-4 font-medium">Target Application</th>
                <th className="px-6 py-4 font-medium">Vector / Endpoint</th>
                <th className="px-6 py-4 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(f => (
                <tr key={f.id} className="hover:bg-surface-2/50 transition-colors">
                  <td className="px-6 py-4">
                    <Badge variant={f.severity === 'CRITICAL' ? 'destructive' : f.severity === 'HIGH' ? 'destructive' : f.severity === 'MEDIUM' ? 'warning' : 'secondary'}>
                      {f.severity}
                    </Badge>
                  </td>
                  <td className="px-6 py-4 font-medium text-foreground">
                    <Link to={`/findings/${f.id}`} className="hover:text-primary hover:underline">
                      {f.title}
                    </Link>
                  </td>
                  <td className="px-6 py-4 text-muted-foreground">{f.application}</td>
                  <td className="px-6 py-4 font-mono text-xs text-muted-foreground">{f.endpoint}</td>
                  <td className="px-6 py-4">
                    <Badge variant={f.status === 'OPEN' ? 'outline' : 'success'}>
                      {f.status}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  )
}
