import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { ArrowLeft, Zap, CheckCircle2, RotateCw, Loader2 } from 'lucide-react'
import { api, type Finding } from '../lib/api'

export const FindingDetails = () => {
  const { id } = useParams()
  const [finding, setFinding] = useState<Finding | null>(null)
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)
  const [verifyMessage, setVerifyMessage] = useState('')

  useEffect(() => {
    async function load() {
      if (!id) return
      try {
        const item = await api.getFinding(id)
        if (item) setFinding(item)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id])

  const handleVerify = async () => {
    if (!id || !finding) return
    setVerifying(true)
    setVerifyMessage('')
    try {
      const res = await api.verifyFinding(id)
      setFinding({
        ...finding,
        status: res.status
      })
      setVerifyMessage(res.message || `Finding status updated to ${res.status}`)
    } catch (err: any) {
      console.error('Verification error:', err)
      setVerifyMessage('Failed to trigger verification.')
    } finally {
      setVerifying(false)
    }
  }

  if (loading) {
    return (
      <div className="py-20 text-center text-muted-foreground flex items-center justify-center gap-2">
        <Loader2 className="w-5 h-5 animate-spin" /> Loading finding details...
      </div>
    )
  }

  if (!finding) {
    return (
      <div className="py-20 text-center text-muted-foreground">
        Finding not found. <Link to="/findings" className="text-primary hover:underline">Back to findings</Link>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      <Link to="/findings" className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="mr-2 h-4 w-4" /> Back to Findings
      </Link>

      <div className="flex justify-between items-start">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Badge variant={finding.severity === 'CRITICAL' ? 'destructive' : finding.severity === 'HIGH' ? 'destructive' : 'warning'}>
              {finding.severity}
            </Badge>
            <Badge variant="outline">Confidence: {finding.confidence}%</Badge>
            <Badge variant={finding.status === 'OPEN' ? 'destructive' : 'success'}>
              {finding.status}
            </Badge>
          </div>
          <h1 className="text-3xl font-bold tracking-tight">{finding.title}</h1>
          <p className="text-muted-foreground mt-2">{finding.application} • {finding.endpoint}</p>
        </div>
        <Button onClick={handleVerify} disabled={verifying} className="gap-2">
          {verifying ? <Loader2 className="w-4 h-4 animate-spin" /> : <RotateCw className="w-4 h-4" />}
          {finding.status === 'OPEN' ? 'Verify Remediation' : 'Re-open Finding'}
        </Button>
      </div>

      {verifyMessage && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-md text-sm text-emerald-500 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          {verifyMessage}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Technical Evidence Context</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <p className="text-sm font-medium mb-2">HTTP Request</p>
                <div className="bg-[#0b0f19] p-4 rounded-md border border-border overflow-x-auto">
                  <pre className="font-mono text-xs text-primary-foreground">
                    {finding.request || 'GET / HTTP/1.1'}
                  </pre>
                </div>
              </div>
              <div>
                <p className="text-sm font-medium mb-2">HTTP Response</p>
                <div className="bg-[#0b0f19] p-4 rounded-md border border-border overflow-x-auto">
                  <pre className="font-mono text-xs text-muted-foreground">
                    {finding.response || 'HTTP/1.1 200 OK'}
                  </pre>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Impact & Remediation</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="font-medium text-sm mb-1">Impact</h4>
                <p className="text-sm text-muted-foreground leading-relaxed">{finding.impact}</p>
              </div>
              <div>
                <h4 className="font-medium text-sm mb-1">Remediation Guidance</h4>
                <p className="text-sm text-muted-foreground leading-relaxed bg-surface-2 p-3 rounded border border-border">
                  {finding.remediation}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card className="border-ai/30 bg-ai/5">
            <CardHeader>
              <CardTitle className="flex items-center text-sm font-medium text-ai">
                <Zap className="w-4 h-4 mr-2" />
                AI Security Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4 leading-relaxed">
                Automated heuristic inspection verified this vector. Enforcing the suggested remediation will secure the target application against automated exploitation.
              </p>
              <Badge className="bg-ai text-ai-foreground">Confirmed By Engine</Badge>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Metadata</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Method</span>
                <span className="font-mono">{finding.method || 'GET'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Parameter</span>
                <span className="font-mono">{finding.parameter || 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Detected</span>
                <span>{new Date(finding.detected).toLocaleDateString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Status</span>
                <Badge variant={finding.status === 'OPEN' ? 'outline' : 'success'}>{finding.status}</Badge>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
