import { useState, useEffect } from 'react'
import { Card, CardContent } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { FileText, Download } from 'lucide-react'
import { api, type Report } from '../lib/api'

export const Reports = () => {
  const [reports, setReports] = useState<Report[]>([])

  useEffect(() => {
    async function load() {
      const data = await api.getReports()
      setReports(data)
    }
    load()
  }, [])

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security & Compliance Reports</h1>
          <p className="text-muted-foreground mt-1">Download and export vulnerability audit logs and executive summaries.</p>
        </div>
        <Button>Generate Report</Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {reports.map(r => (
          <Card key={r.id} className="hover:border-primary/50 transition-colors">
            <CardContent className="p-6 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="h-10 w-10 bg-surface-2 rounded-full flex items-center justify-center border border-border">
                  <FileText className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-semibold">{r.name}</h3>
                  <p className="text-xs text-muted-foreground mt-0.5">{r.application} • {r.date}</p>
                </div>
              </div>
              <Button variant="outline" size="sm" className="gap-2" onClick={() => window.print()}>
                <Download className="h-4 w-4" /> Export
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
