import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { 
  Globe, MapPin, TrendingUp, Users, MousePointer, Eye,
  ArrowUpDown, ChevronDown, ChevronUp, Search, RefreshCw,
  Flag, BarChart3, PieChart, Activity, Target
} from 'lucide-react'
import { API_ENDPOINTS } from '../config'

const GeographyPage = ({ user, token }) => {
  const [overviewData, setOverviewData] = useState(null)
  const [rankingData, setRankingData] = useState([])
  const [engagementData, setEngagementData] = useState({})
  const [linkPerformanceData, setLinkPerformanceData] = useState({})
  const [loading, setLoading] = useState(true)
  const [sortField, setSortField] = useState('clicks')
  const [sortDirection, setSortDirection] = useState('desc')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCountry, setSelectedCountry] = useState(null)
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    fetchGeographyData()
  }, [])

  const fetchGeographyData = async () => {
    try {
      setLoading(true)
      
      // Fetch all geography data
      const [overviewRes, rankingRes, engagementRes, performanceRes] = await Promise.all([
        fetch(`${API_ENDPOINTS.BASE}/api/geography/overview`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_ENDPOINTS.BASE}/api/geography/ranking`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_ENDPOINTS.BASE}/api/geography/engagement`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_ENDPOINTS.BASE}/api/geography/link-performance`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ])

      if (overviewRes.ok) {
        const data = await overviewRes.json()
        setOverviewData(data)
      }

      if (rankingRes.ok) {
        const data = await rankingRes.json()
        setRankingData(data.countries || [])
      }

      if (engagementRes.ok) {
        const data = await engagementRes.json()
        setEngagementData(data.engagement_by_location || {})
      }

      if (performanceRes.ok) {
        const data = await performanceRes.json()
        setLinkPerformanceData(data.link_performance || {})
      }

    } catch (error) {
      console.error('Failed to fetch geography data:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDirection('desc')
    }
  }

  const getSortedRankingData = () => {
    const filtered = rankingData.filter(country => 
      country.country_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      country.country_code.toLowerCase().includes(searchTerm.toLowerCase())
    )

    return filtered.sort((a, b) => {
      const aVal = a[sortField]
      const bVal = b[sortField]
      const multiplier = sortDirection === 'asc' ? 1 : -1
      
      if (typeof aVal === 'number' && typeof bVal === 'number') {
        return (aVal - bVal) * multiplier
      }
      return aVal.toString().localeCompare(bVal.toString()) * multiplier
    })
  }

  const getEngagementColor = (score) => {
    if (score >= 80) return 'bg-green-100 text-green-800'
    if (score >= 60) return 'bg-yellow-100 text-yellow-800'
    if (score >= 40) return 'bg-orange-100 text-orange-800'
    return 'bg-red-100 text-red-800'
  }

  const WorldMapHeatmap = ({ data }) => {
    if (!data || !data.heatmap_data) return null

    const maxClicks = Math.max(...data.heatmap_data.map(d => d.click_count))

    return (
      <div className="relative">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-2 sm:gap-4">
          {data.heatmap_data.slice(0, 24).map((country) => {
            const intensity = (country.click_count / maxClicks) * 100
            const bgOpacity = Math.max(0.1, intensity / 100)
            
            return (
              <Card 
                key={country.country_code}
                className={`cursor-pointer transition-all hover:shadow-md ${
                  selectedCountry === country.country_code ? 'ring-2 ring-blue-500' : ''
                }`}
                onClick={() => setSelectedCountry(
                  selectedCountry === country.country_code ? null : country.country_code
                )}
                style={{
                  backgroundColor: `rgba(59, 130, 246, ${bgOpacity})`
                }}
              >
                <CardContent className="p-2 sm:p-3">
                  <div className="flex items-center space-x-2">
                    <img 
                      src={`https://flagcdn.com/24x18/${country.country_code.toLowerCase()}.png`}
                      alt={country.country_name}
                      className="w-4 h-3 sm:w-6 sm:h-4"
                      onError={(e) => {
                        e.target.style.display = 'none'
                      }}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs sm:text-sm font-medium truncate">
                        {country.country_name}
                      </p>
                      <p className="text-xs text-gray-600">
                        {country.click_count} clicks ({country.percentage}%)
                      </p>
                    </div>
                  </div>
                  
                  {selectedCountry === country.country_code && (
                    <div className="mt-2 pt-2 border-t">
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span>Unique Visitors:</span>
                          <span>{country.unique_visitors}</span>
                        </div>
                        <div className="flex justify-between text-xs">
                          <span>Success Rate:</span>
                          <span>{country.success_rate}%</span>
                        </div>
                        {country.top_links.length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs font-medium">Top Links:</p>
                            {country.top_links.slice(0, 2).map((link, idx) => (
                              <div key={idx} className="text-xs text-gray-600 truncate">
                                {link.clicks}x - {link.url.substring(0, 30)}...
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )
          })}
        </div>
      </div>
    )
  }

  const CountryRankingTable = ({ data }) => {
    const sortedData = getSortedRankingData()

    return (
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              placeholder="Search countries..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
          <Button variant="outline" onClick={fetchGeographyData}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {/* Mobile View */}
        <div className="block sm:hidden space-y-3">
          {sortedData.map((country) => (
            <Card key={country.country_code}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <Badge variant="secondary" className="text-xs">
                      #{country.rank}
                    </Badge>
                    <img 
                      src={country.flag}
                      alt={country.country_name}
                      className="w-6 h-4"
                      onError={(e) => e.target.style.display = 'none'}
                    />
                    <span className="font-medium">{country.country_name}</span>
                  </div>
                  <Badge className={getEngagementColor(country.engagement_score)}>
                    {country.engagement_score}
                  </Badge>
                </div>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <span className="text-gray-600">Clicks:</span>
                    <span className="ml-2 font-medium">{country.clicks}</span>
                  </div>
                  <div>
                    <span className="text-gray-600">Opens:</span>
                    <span className="ml-2 font-medium">{country.opens}</span>
                  </div>
                  <div>
                    <span className="text-gray-600">Visitors:</span>
                    <span className="ml-2 font-medium">{country.unique_visitors}</span>
                  </div>
                  <div>
                    <span className="text-gray-600">CTR:</span>
                    <span className="ml-2 font-medium">{country.ctr}%</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Desktop View */}
        <div className="hidden sm:block overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left p-3">
                  <Button variant="ghost" size="sm" onClick={() => handleSort('rank')}>
                    Rank <ArrowUpDown className="h-3 w-3 ml-1" />
                  </Button>
                </th>
                <th className="text-left p-3">Country</th>
                <th className="text-left p-3">
                  <Button variant="ghost" size="sm" onClick={() => handleSort('clicks')}>
                    Clicks <ArrowUpDown className="h-3 w-3 ml-1" />
                  </Button>
                </th>
                <th className="text-left p-3">
                  <Button variant="ghost" size="sm" onClick={() => handleSort('opens')}>
                    Opens <ArrowUpDown className="h-3 w-3 ml-1" />
                  </Button>
                </th>
                <th className="text-left p-3">
                  <Button variant="ghost" size="sm" onClick={() => handleSort('percentage')}>
                    % of Total <ArrowUpDown className="h-3 w-3 ml-1" />
                  </Button>
                </th>
                <th className="text-left p-3">
                  <Button variant="ghost" size="sm" onClick={() => handleSort('ctr')}>
                    CTR <ArrowUpDown className="h-3 w-3 ml-1" />
                  </Button>
                </th>
                <th className="text-left p-3">
                  <Button variant="ghost" size="sm" onClick={() => handleSort('engagement_score')}>
                    Engagement <ArrowUpDown className="h-3 w-3 ml-1" />
                  </Button>
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedData.map((country) => (
                <tr key={country.country_code} className="border-b hover:bg-gray-50">
                  <td className="p-3">
                    <Badge variant="secondary">#{country.rank}</Badge>
                  </td>
                  <td className="p-3">
                    <div className="flex items-center space-x-3">
                      <img 
                        src={country.flag}
                        alt={country.country_name}
                        className="w-6 h-4"
                        onError={(e) => e.target.style.display = 'none'}
                      />
                      <span className="font-medium">{country.country_name}</span>
                    </div>
                  </td>
                  <td className="p-3 font-medium">{country.clicks.toLocaleString()}</td>
                  <td className="p-3">{country.opens.toLocaleString()}</td>
                  <td className="p-3">{country.percentage}%</td>
                  <td className="p-3">{country.ctr}%</td>
                  <td className="p-3">
                    <Badge className={getEngagementColor(country.engagement_score)}>
                      {country.engagement_score}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )
  }

  const EngagementAnalysis = ({ data }) => {
    const countries = Object.entries(data)

    return (
      <div className="space-y-4">
        {countries.map(([countryCode, countryData]) => (
          <Card key={countryCode}>
            <CardHeader>
              <CardTitle className="flex items-center space-x-3">
                <img 
                  src={`https://flagcdn.com/24x18/${countryCode.toLowerCase()}.png`}
                  alt={countryData.country_name}
                  className="w-6 h-4"
                  onError={(e) => e.target.style.display = 'none'}
                />
                <span>{countryData.country_name}</span>
                <Badge className={getEngagementColor(countryData.avg_engagement_score || 0)}>
                  Engagement: {countryData.avg_engagement_score || 0}
                </Badge>
              </CardTitle>
              <CardDescription>
                {countryData.total_clicks} total clicks • {countryData.engaged_cities_count} engaged cities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {countryData.cities.slice(0, 6).map((city, idx) => (
                  <div key={idx} className="p-3 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium">{city.city}</span>
                      {city.is_engaged && (
                        <Badge className="bg-green-100 text-green-800 text-xs">
                          Engaged
                        </Badge>
                      )}
                    </div>
                    <div className="space-y-1 text-sm text-gray-600">
                      <div className="flex justify-between">
                        <span>Clicks:</span>
                        <span>{city.clicks}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Bounce Rate:</span>
                        <span>{city.bounce_rate}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Success Rate:</span>
                        <span>{city.success_rate}%</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }

  const LinkPerformanceAnalysis = ({ data }) => {
    const links = Object.entries(data)

    return (
      <div className="space-y-4">
        {links.map(([url, linkData]) => (
          <Card key={url}>
            <CardHeader>
              <CardTitle className="text-sm sm:text-base break-all">
                {url}
              </CardTitle>
              <CardDescription>
                {linkData.total_clicks} total clicks • {linkData.regions.length} regions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {/* Best and Worst Performing Regions */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {linkData.best_performing_region && (
                    <div className="p-3 bg-green-50 border border-green-200 rounded-lg">
                      <div className="flex items-center space-x-2 mb-2">
                        <TrendingUp className="h-4 w-4 text-green-600" />
                        <span className="font-medium text-green-800">Best Performing</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <img 
                          src={`https://flagcdn.com/16x12/${linkData.best_performing_region.country_code.toLowerCase()}.png`}
                          alt={linkData.best_performing_region.country_name}
                          className="w-4 h-3"
                          onError={(e) => e.target.style.display = 'none'}
                        />
                        <span className="text-sm">{linkData.best_performing_region.country_name}</span>
                      </div>
                      <div className="text-xs text-green-700 mt-1">
                        {linkData.best_performing_region.clicks} clicks • Score: {linkData.best_performing_region.performance_score}
                      </div>
                    </div>
                  )}

                  {linkData.worst_performing_region && (
                    <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                      <div className="flex items-center space-x-2 mb-2">
                        <Target className="h-4 w-4 text-red-600" />
                        <span className="font-medium text-red-800">Needs Improvement</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <img 
                          src={`https://flagcdn.com/16x12/${linkData.worst_performing_region.country_code.toLowerCase()}.png`}
                          alt={linkData.worst_performing_region.country_name}
                          className="w-4 h-3"
                          onError={(e) => e.target.style.display = 'none'}
                        />
                        <span className="text-sm">{linkData.worst_performing_region.country_name}</span>
                      </div>
                      <div className="text-xs text-red-700 mt-1">
                        {linkData.worst_performing_region.clicks} clicks • Score: {linkData.worst_performing_region.performance_score}
                      </div>
                    </div>
                  )}
                </div>

                {/* Underperforming Regions */}
                {linkData.underperforming_regions && linkData.underperforming_regions.length > 0 && (
                  <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                    <div className="flex items-center space-x-2 mb-2">
                      <Activity className="h-4 w-4 text-yellow-600" />
                      <span className="font-medium text-yellow-800">
                        Underperforming Regions ({linkData.underperforming_regions.length})
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {linkData.underperforming_regions.slice(0, 5).map((region, idx) => (
                        <div key={idx} className="flex items-center space-x-1 text-xs bg-white px-2 py-1 rounded">
                          <img 
                            src={`https://flagcdn.com/16x12/${region.country_code.toLowerCase()}.png`}
                            alt={region.country_name}
                            className="w-3 h-2"
                            onError={(e) => e.target.style.display = 'none'}
                          />
                          <span>{region.country_name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* All Regions Performance */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {linkData.regions.slice(0, 9).map((region, idx) => (
                    <div key={idx} className="p-2 border rounded text-xs">
                      <div className="flex items-center space-x-2 mb-1">
                        <img 
                          src={`https://flagcdn.com/16x12/${region.country_code.toLowerCase()}.png`}
                          alt={region.country_name}
                          className="w-4 h-3"
                          onError={(e) => e.target.style.display = 'none'}
                        />
                        <span className="font-medium">{region.country_name}</span>
                      </div>
                      <div className="space-y-1 text-gray-600">
                        <div className="flex justify-between">
                          <span>Clicks:</span>
                          <span>{region.clicks}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Score:</span>
                          <span>{region.performance_score}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="text-center py-8">
          <Globe className="h-16 w-16 mx-auto text-gray-400 mb-4 animate-pulse" />
          <p className="text-gray-600">Loading geography data...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      {/* Tab Navigation */}
      <div className="flex flex-wrap gap-2">
        {[
          { id: 'overview', label: 'World Map', icon: Globe },
          { id: 'ranking', label: 'Country Ranking', icon: BarChart3 },
          { id: 'engagement', label: 'Engagement Quality', icon: Activity },
          { id: 'performance', label: 'Link Performance', icon: Target }
        ].map(tab => {
          const IconComponent = tab.icon
          return (
            <Button
              key={tab.id}
              variant={activeTab === tab.id ? 'default' : 'outline'}
              size="sm"
              onClick={() => setActiveTab(tab.id)}
              className="flex items-center space-x-2"
            >
              <IconComponent className="h-4 w-4" />
              <span className="hidden sm:inline">{tab.label}</span>
              <span className="sm:hidden">{tab.label.split(' ')[0]}</span>
            </Button>
          )
        })}
      </div>

      {/* Overview Stats */}
      {overviewData && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 sm:gap-4">
          <Card>
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center space-x-2">
                <Globe className="h-4 w-4 text-blue-500" />
                <div>
                  <p className="text-xs sm:text-sm font-medium text-gray-600">Total Countries</p>
                  <p className="text-lg sm:text-2xl font-bold">{overviewData.total_countries}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center space-x-2">
                <MousePointer className="h-4 w-4 text-green-500" />
                <div>
                  <p className="text-xs sm:text-sm font-medium text-gray-600">Global Clicks</p>
                  <p className="text-lg sm:text-2xl font-bold">{overviewData.total_clicks?.toLocaleString()}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center space-x-2">
                <MapPin className="h-4 w-4 text-purple-500" />
                <div>
                  <p className="text-xs sm:text-sm font-medium text-gray-600">Top Region</p>
                  <p className="text-sm sm:text-lg font-bold">
                    {overviewData.heatmap_data?.[0]?.country_name || 'N/A'}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Globe className="h-5 w-5" />
              <span>Interactive World Map</span>
            </CardTitle>
            <CardDescription>
              Click density heatmap by country. Click on countries for detailed information.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <WorldMapHeatmap data={overviewData} />
          </CardContent>
        </Card>
      )}

      {activeTab === 'ranking' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <BarChart3 className="h-5 w-5" />
              <span>Country/Region Ranking</span>
            </CardTitle>
            <CardDescription>
              Sortable ranking of countries by performance metrics
            </CardDescription>
          </CardHeader>
          <CardContent>
            <CountryRankingTable data={rankingData} />
          </CardContent>
        </Card>
      )}

      {activeTab === 'engagement' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Activity className="h-5 w-5" />
              <span>Engagement Quality by Location</span>
            </CardTitle>
            <CardDescription>
              Bounce rates and engagement scores by country and city
            </CardDescription>
          </CardHeader>
          <CardContent>
            <EngagementAnalysis data={engagementData} />
          </CardContent>
        </Card>
      )}

      {activeTab === 'performance' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Target className="h-5 w-5" />
              <span>Link Performance by Region</span>
            </CardTitle>
            <CardDescription>
              Performance analysis of individual links across different regions
            </CardDescription>
          </CardHeader>
          <CardContent>
            <LinkPerformanceAnalysis data={linkPerformanceData} />
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export default GeographyPage

