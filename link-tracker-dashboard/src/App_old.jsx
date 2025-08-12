import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Progress } from '@/components/ui/progress'
import TrackingLinksPage from '@/components/TrackingLinksPage'
import { Toaster } from 'sonner'
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, PieChart, Pie, Cell, Area, AreaChart
} from 'recharts'
import { 
  Activity, Users, MousePointer, Mail, Shield, Globe, 
  TrendingUp, AlertTriangle, Eye, Clock, MapPin, Smartphone,
  RefreshCw, Download, Trash2, Settings, Filter
} from 'lucide-react'
import './App.css'

// Mock data for demonstration
const mockAnalytics = {
  overview: {
    totalClicks: 1247,
    totalOpens: 3891,
    uniqueVisitors: 892,
    conversionRate: 32.1,
    blockedRequests: 156,
    riskScore: 0.23
  },
  hourlyActivity: [
    { hour: '00:00', clicks: 12, opens: 45, blocked: 3 },
    { hour: '01:00', clicks: 8, opens: 23, blocked: 1 },
    { hour: '02:00', clicks: 5, opens: 18, blocked: 2 },
    { hour: '03:00', clicks: 3, opens: 12, blocked: 1 },
    { hour: '04:00', clicks: 7, opens: 19, blocked: 0 },
    { hour: '05:00', clicks: 15, opens: 34, blocked: 2 },
    { hour: '06:00', clicks: 28, opens: 67, blocked: 4 },
    { hour: '07:00', clicks: 45, opens: 123, blocked: 8 },
    { hour: '08:00', clicks: 89, opens: 234, blocked: 12 },
    { hour: '09:00', clicks: 156, opens: 345, blocked: 18 },
    { hour: '10:00', clicks: 134, opens: 298, blocked: 15 },
    { hour: '11:00', clicks: 167, opens: 387, blocked: 21 },
    { hour: '12:00', clicks: 145, opens: 321, blocked: 19 },
    { hour: '13:00', clicks: 123, opens: 287, blocked: 16 },
    { hour: '14:00', clicks: 134, opens: 312, blocked: 17 },
    { hour: '15:00', clicks: 156, opens: 356, blocked: 22 },
    { hour: '16:00', clicks: 89, opens: 234, blocked: 14 },
    { hour: '17:00', clicks: 67, opens: 189, blocked: 11 },
    { hour: '18:00', clicks: 45, opens: 134, blocked: 8 },
    { hour: '19:00', clicks: 34, opens: 98, blocked: 6 },
    { hour: '20:00', clicks: 28, opens: 76, blocked: 4 },
    { hour: '21:00', clicks: 23, opens: 65, blocked: 3 },
    { hour: '22:00', clicks: 18, opens: 54, blocked: 2 },
    { hour: '23:00', clicks: 15, opens: 43, blocked: 2 }
  ],
  topCountries: [
    { country: 'United States', code: 'US', clicks: 456, opens: 1234, percentage: 31.7 },
    { country: 'United Kingdom', code: 'GB', clicks: 234, opens: 678, percentage: 18.8 },
    { country: 'Canada', code: 'CA', clicks: 189, opens: 543, percentage: 15.1 },
    { country: 'Australia', code: 'AU', clicks: 123, opens: 345, percentage: 9.9 },
    { country: 'Germany', code: 'DE', clicks: 98, opens: 287, percentage: 7.9 },
    { country: 'France', code: 'FR', clicks: 87, opens: 234, percentage: 6.8 },
    { country: 'Other', code: 'XX', clicks: 60, opens: 170, percentage: 9.8 }
  ],
  deviceTypes: [
    { name: 'Desktop', value: 45.2, count: 567 },
    { name: 'Mobile', value: 38.7, count: 485 },
    { name: 'Tablet', value: 16.1, count: 202 }
  ],
  securityEvents: [
    { type: 'Bot Detected', count: 89, severity: 'high' },
    { type: 'Rate Limited', count: 34, severity: 'medium' },
    { type: 'Geo Blocked', count: 23, severity: 'medium' },
    { type: 'Invalid Email', count: 10, severity: 'low' }
  ],
  recentActivity: [
    { time: '2 min ago', event: 'Email opened', location: 'New York, US', device: 'iPhone', status: 'success' },
    { time: '5 min ago', event: 'Link clicked', location: 'London, UK', device: 'Chrome Desktop', status: 'success' },
    { time: '8 min ago', event: 'Bot blocked', location: 'Unknown', device: 'curl/7.68.0', status: 'blocked' },
    { time: '12 min ago', event: 'Email opened', location: 'Toronto, CA', device: 'Android', status: 'success' },
    { time: '15 min ago', event: 'Rate limited', location: 'Berlin, DE', device: 'Firefox', status: 'limited' }
  ]
}

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6']

function App() {
  const [analytics, setAnalytics] = useState(mockAnalytics)
  const [isLoading, setIsLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(new Date())

  const refreshData = async () => {
    setIsLoading(true)
    // Simulate API call
    setTimeout(() => {
      setLastUpdated(new Date())
      setIsLoading(false)
    }, 1000)
  }

  const getRiskColor = (score) => {
    if (score < 0.3) return 'text-green-600'
    if (score < 0.6) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'success': return 'bg-green-100 text-green-800'
      case 'blocked': return 'bg-red-100 text-red-800'
      case 'limited': return 'bg-yellow-100 text-yellow-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      {/* Header */}
      <div className="border-b bg-white/80 backdrop-blur-sm dark:bg-slate-900/80 sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Shield className="h-8 w-8 text-blue-600" />
                <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  7th Brain Link Tracker
                </h1>
              </div>
              <Badge variant="outline" className="text-xs">
                Advanced Analytics
              </Badge>
            </div>
            
            <div className="flex items-center space-x-3">
              <div className="text-sm text-muted-foreground">
                Last updated: {lastUpdated.toLocaleTimeString()}
              </div>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={refreshData}
                disabled={isLoading}
                className="flex items-center space-x-2"
              >
                <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </Button>
              <Button variant="outline" size="sm">
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
              <Button variant="outline" size="sm">
                <Settings className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-6 py-8">
        {/* Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-6 mb-8">
          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Clicks</CardTitle>
              <MousePointer className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">{analytics.overview.totalClicks.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground">
                <TrendingUp className="inline h-3 w-3 mr-1" />
                +12.5% from last week
              </p>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Email Opens</CardTitle>
              <Mail className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{analytics.overview.totalOpens.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground">
                <TrendingUp className="inline h-3 w-3 mr-1" />
                +8.2% from last week
              </p>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Unique Visitors</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-600">{analytics.overview.uniqueVisitors.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground">
                <TrendingUp className="inline h-3 w-3 mr-1" />
                +5.7% from last week
              </p>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Conversion Rate</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-600">{analytics.overview.conversionRate}%</div>
              <p className="text-xs text-muted-foreground">
                <TrendingUp className="inline h-3 w-3 mr-1" />
                +2.1% from last week
              </p>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Blocked Requests</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{analytics.overview.blockedRequests.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground">
                <AlertTriangle className="inline h-3 w-3 mr-1" />
                Security active
              </p>
            </CardContent>
          </Card>

          <Card className="hover:shadow-lg transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${getRiskColor(analytics.overview.riskScore)}`}>
                {(analytics.overview.riskScore * 100).toFixed(1)}%
              </div>
              <Progress value={analytics.overview.riskScore * 100} className="mt-2" />
            </CardContent>
          </Card>
        </div>

        {/* Main Dashboard */}
        <Tabs defaultValue="analytics" className="space-y-6">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
            <TabsTrigger value="tracking">Tracking Links</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
            <TabsTrigger value="geography">Geography</TabsTrigger>
            <TabsTrigger value="activity">Live Activity</TabsTrigger>
          </TabsList>

          <TabsContent value="analytics" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Hourly Activity Chart */}
              <Card className="col-span-2">
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Clock className="h-5 w-5" />
                    <span>Hourly Activity</span>
                  </CardTitle>
                  <CardDescription>
                    Email opens, link clicks, and blocked requests over the last 24 hours
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={analytics.hourlyActivity}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="hour" />
                      <YAxis />
                      <Tooltip />
                      <Area type="monotone" dataKey="opens" stackId="1" stroke="#10b981" fill="#10b981" fillOpacity={0.6} />
                      <Area type="monotone" dataKey="clicks" stackId="1" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.8} />
                      <Area type="monotone" dataKey="blocked" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.4} />
                    </AreaChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              {/* Device Types */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Smartphone className="h-5 w-5" />
                    <span>Device Types</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie
                        data={analytics.deviceTypes}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, value }) => `${name}: ${value}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {analytics.deviceTypes.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="tracking" className="space-y-6">
            <TrackingLinksPage />
          </TabsContent>

          <TabsContent value="security" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Security Events */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Shield className="h-5 w-5" />
                    <span>Security Events</span>
                  </CardTitle>
                  <CardDescription>
                    Blocked requests and security incidents
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {analytics.securityEvents.map((event, index) => (
                      <div key={index} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                        <div className="flex items-center space-x-3">
                          <div className={`w-3 h-3 rounded-full ${
                            event.severity === 'high' ? 'bg-red-500' :
                            event.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                          }`} />
                          <span className="font-medium">{event.type}</span>
                        </div>
                        <Badge variant="outline">{event.count}</Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Security Features Status */}
              <Card>
                <CardHeader>
                  <CardTitle>Security Features</CardTitle>
                  <CardDescription>
                    Advanced protection status
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span>Social Referrer Firewall</span>
                      <Badge className="bg-green-100 text-green-800">Active</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Bot Detection AI</span>
                      <Badge className="bg-green-100 text-green-800">Learning</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Rate Limiting</span>
                      <Badge className="bg-green-100 text-green-800">Active</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>MX Verification</span>
                      <Badge className="bg-green-100 text-green-800">Enabled</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Dynamic Signatures</span>
                      <Badge className="bg-green-100 text-green-800">Active</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Geo-Filtering</span>
                      <Badge className="bg-green-100 text-green-800">Active</Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="geography" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Globe className="h-5 w-5" />
                  <span>Geographic Distribution</span>
                </CardTitle>
                <CardDescription>
                  Traffic breakdown by country
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {analytics.topCountries.map((country, index) => (
                    <div key={index} className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="w-8 h-6 bg-muted rounded flex items-center justify-center text-xs font-mono">
                          {country.code}
                        </div>
                        <span className="font-medium">{country.country}</span>
                      </div>
                      <div className="flex items-center space-x-4">
                        <div className="text-sm text-muted-foreground">
                          {country.clicks} clicks, {country.opens} opens
                        </div>
                        <div className="w-20">
                          <Progress value={country.percentage} />
                        </div>
                        <div className="text-sm font-medium w-12 text-right">
                          {country.percentage}%
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="activity" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Eye className="h-5 w-5" />
                  <span>Live Activity Feed</span>
                </CardTitle>
                <CardDescription>
                  Real-time tracking events and security incidents
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {analytics.recentActivity.map((activity, index) => (
                    <div key={index} className="flex items-center justify-between p-4 rounded-lg border">
                      <div className="flex items-center space-x-4">
                        <div className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(activity.status)}`}>
                          {activity.status}
                        </div>
                        <div>
                          <div className="font-medium">{activity.event}</div>
                          <div className="text-sm text-muted-foreground">
                            {activity.location} • {activity.device}
                          </div>
                        </div>
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {activity.time}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
      <Toaster />
    </div>
  )
}

export default App

