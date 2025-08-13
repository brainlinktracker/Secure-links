import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { 
  Activity, Search, RefreshCw, ChevronLeft, ChevronRight, 
  Globe, Shield, TrendingUp, Users, Eye, MousePointer,
  AlertTriangle, CheckCircle, XCircle, Clock
} from 'lucide-react'
import { API_ENDPOINTS } from '../config'

const LiveActivityPage = ({ user, token }) => {
  const [events, setEvents] = useState([])
  const [analytics, setAnalytics] = useState(null)
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [pagination, setPagination] = useState({})
  const [refreshing, setRefreshing] = useState(false)

  const perPage = 30

  useEffect(() => {
    if (token) {
      fetchLiveActivity()
      fetchAnalytics()
      // Auto-refresh every 30 seconds
      const interval = setInterval(() => {
        fetchLiveActivity(false)
        fetchAnalytics()
      }, 30000)
      return () => clearInterval(interval)
    }
  }, [currentPage, searchTerm, token])

  const fetchLiveActivity = async (showLoading = true) => {
    try {
      if (showLoading) setLoading(true)
      const params = new URLSearchParams({
        page: currentPage.toString(),
        per_page: perPage.toString(),
        ...(searchTerm && { search: searchTerm })
      })

      const response = await fetch(`${API_ENDPOINTS.BASE}/api/tracking-events?${params}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const data = await response.json()
        setEvents(data || [])
        // Set basic pagination if not provided
        setPagination({
          total: data.length,
          total_pages: Math.ceil(data.length / perPage),
          has_prev: currentPage > 1,
          has_next: data.length === perPage
        })
      }
    } catch (error) {
      console.error('Failed to fetch live activity:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchAnalytics = async () => {
    try {
      const response = await fetch(`${API_ENDPOINTS.BASE}/api/analytics/summary`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const data = await response.json()
        setAnalytics({
          total_clicks: data.total_clicks || 0,
          total_redirects: data.total_clicks || 0,
          bot_blocks: data.bot_clicks || 0,
          real_visitors: data.unique_visitors || 0,
          email_opens: 0,
          recent_activity_24h: data.total_clicks || 0
        })
      }
    } catch (error) {
      console.error('Failed to fetch analytics:', error)
    }
  }

  const handleSearch = (e) => {
    setSearchTerm(e.target.value)
    setCurrentPage(1) // Reset to first page when searching
  }

  const handleRefresh = async () => {
    setRefreshing(true)
    await fetchLiveActivity()
    await fetchAnalytics()
    setRefreshing(false)
  }

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleString()
  }

  const getStatusBadge = (status) => {
    const statusConfig = {
      'sent': { color: 'bg-blue-100 text-blue-800', icon: Clock },
      'opened': { color: 'bg-green-100 text-green-800', icon: Eye },
      'clicked': { color: 'bg-yellow-100 text-yellow-800', icon: MousePointer },
      'redirected': { color: 'bg-green-100 text-green-800', icon: CheckCircle },
      'blocked': { color: 'bg-red-100 text-red-800', icon: XCircle },
      'processed': { color: 'bg-gray-100 text-gray-800', icon: CheckCircle }
    }

    const config = statusConfig[status] || statusConfig['processed']
    const IconComponent = config.icon

    return (
      <Badge className={`${config.color} flex items-center space-x-1`}>
        <IconComponent className="h-3 w-3" />
        <span className="capitalize">{status}</span>
      </Badge>
    )
  }

  const truncateText = (text, maxLength = 30) => {
    if (!text) return 'N/A'
    return text.length > maxLength ? `${text.substring(0, maxLength)}...` : text
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      {/* Analytics Cards */}
      {analytics && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
          <Card>
            <CardContent className="p-3 sm:p-4">
              <div className="flex flex-col space-y-1">
                <div className="flex items-center space-x-2">
                  <MousePointer className="h-4 w-4 text-blue-500" />
                  <p className="text-xs sm:text-sm font-medium text-gray-600">Total Clicks</p>
                </div>
                <p className="text-lg sm:text-2xl font-bold text-gray-900">{analytics.total_clicks}</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-3 sm:p-4">
              <div className="flex flex-col space-y-1">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <p className="text-xs sm:text-sm font-medium text-gray-600">Redirects</p>
                </div>
                <p className="text-lg sm:text-2xl font-bold text-gray-900">{analytics.total_redirects}</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-3 sm:p-4">
              <div className="flex flex-col space-y-1">
                <div className="flex items-center space-x-2">
                  <Shield className="h-4 w-4 text-red-500" />
                  <p className="text-xs sm:text-sm font-medium text-gray-600">Bot Blocks</p>
                </div>
                <p className="text-lg sm:text-2xl font-bold text-gray-900">{analytics.bot_blocks}</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-3 sm:p-4">
              <div className="flex flex-col space-y-1">
                <div className="flex items-center space-x-2">
                  <Users className="h-4 w-4 text-green-500" />
                  <p className="text-xs sm:text-sm font-medium text-gray-600">Real Visitors</p>
                </div>
                <p className="text-lg sm:text-2xl font-bold text-gray-900">{analytics.real_visitors}</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-3 sm:p-4">
              <div className="flex flex-col space-y-1">
                <div className="flex items-center space-x-2">
                  <Eye className="h-4 w-4 text-purple-500" />
                  <p className="text-xs sm:text-sm font-medium text-gray-600">Email Opens</p>
                </div>
                <p className="text-lg sm:text-2xl font-bold text-gray-900">{analytics.email_opens}</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-3 sm:p-4">
              <div className="flex flex-col space-y-1">
                <div className="flex items-center space-x-2">
                  <TrendingUp className="h-4 w-4 text-orange-500" />
                  <p className="text-xs sm:text-sm font-medium text-gray-600">24h Activity</p>
                </div>
                <p className="text-lg sm:text-2xl font-bold text-gray-900">{analytics.recent_activity_24h}</p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Main Activity Table */}
      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between space-y-3 sm:space-y-0">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Activity className="h-5 w-5" />
                <span>Live Activity</span>
              </CardTitle>
              <CardDescription>
                Real-time tracking events and user interactions
              </CardDescription>
            </div>
            <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search by tracking ID..."
                  value={searchTerm}
                  onChange={handleSearch}
                  className="pl-10 w-full sm:w-64"
                />
              </div>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={handleRefresh}
                disabled={refreshing}
                className="min-w-[100px]"
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8">
              <Activity className="h-16 w-16 mx-auto text-gray-400 mb-4 animate-pulse" />
              <p className="text-gray-600">Loading activity data...</p>
            </div>
          ) : events.length === 0 ? (
            <div className="text-center py-8">
              <Activity className="h-16 w-16 mx-auto text-gray-400 mb-4" />
              <p className="text-gray-600">
                {searchTerm ? 'No events found matching your search.' : 'No activity data available yet.'}
              </p>
            </div>
          ) : (
            <>
              {/* Mobile View */}
              <div className="block sm:hidden space-y-3">
                {events.map((event) => (
                  <Card key={event.id} className="p-3">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-sm text-blue-600">
                          {truncateText(event.tracking_token, 15)}
                        </span>
                        {getStatusBadge(event.status)}
                      </div>
                      <div className="text-xs text-gray-600">
                        <div>🌍 {event.ip_address} • {event.country || 'Unknown'}, {event.city || 'Unknown'}</div>
                        <div>🖥️ {truncateText(event.device_type || 'Unknown', 20)}</div>
                        <div>⏰ {formatTimestamp(event.timestamp)}</div>
                      </div>
                    </div>
                  </Card>
                ))}
              </div>

              {/* Desktop View */}
              <div className="hidden sm:block overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left p-2 font-medium text-gray-600">Timestamp</th>
                      <th className="text-left p-2 font-medium text-gray-600">Tracking ID</th>
                      <th className="text-left p-2 font-medium text-gray-600">IP Address</th>
                      <th className="text-left p-2 font-medium text-gray-600">User Agent</th>
                      <th className="text-left p-2 font-medium text-gray-600">Country</th>
                      <th className="text-left p-2 font-medium text-gray-600">City</th>
                      <th className="text-left p-2 font-medium text-gray-600">Device</th>
                      <th className="text-left p-2 font-medium text-gray-600">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((event) => (
                      <tr key={event.id} className="border-b hover:bg-gray-50">
                        <td className="p-2 text-sm">{formatTimestamp(event.timestamp)}</td>
                        <td className="p-2">
                          <span className="font-mono text-sm text-blue-600">
                            {truncateText(event.tracking_token, 12)}
                          </span>
                        </td>
                        <td className="p-2 text-sm">{event.ip_address}</td>
                        <td className="p-2 text-sm" title={event.user_agent}>
                          {truncateText(event.user_agent, 25)}
                        </td>
                        <td className="p-2 text-sm">{event.country || 'Unknown'}</td>
                        <td className="p-2 text-sm">{event.city || 'Unknown'}</td>
                        <td className="p-2 text-sm">{event.device_type || 'Unknown'}</td>
                        <td className="p-2">{getStatusBadge(event.status)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {pagination.total_pages > 1 && (
                <div className="flex flex-col sm:flex-row items-center justify-between mt-6 space-y-3 sm:space-y-0">
                  <div className="text-sm text-gray-600">
                    Showing {((currentPage - 1) * perPage) + 1} to {Math.min(currentPage * perPage, pagination.total)} of {pagination.total} events
                  </div>
                  <div className="flex items-center space-x-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage(currentPage - 1)}
                      disabled={!pagination.has_prev}
                    >
                      <ChevronLeft className="h-4 w-4" />
                      Previous
                    </Button>
                    <span className="text-sm text-gray-600">
                      Page {currentPage} of {pagination.total_pages}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage(currentPage + 1)}
                      disabled={!pagination.has_next}
                    >
                      Next
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

export default LiveActivityPage

