import React, { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './ui/dialog';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Textarea } from './ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { toast } from 'sonner';
import { 
  User, Plus, Eye, BarChart3, TrendingUp, Activity, 
  Link, Mail, Calendar, Globe, Copy, ExternalLink,
  Target, Users, MousePointer, Shield, AlertCircle,
  FolderPlus, Settings, Trash2, Edit, Play, Pause,
  UserCheck, PersonStanding
} from 'lucide-react';

const IndividualDashboard = ({ user, token }) => {
  const [campaigns, setCampaigns] = useState([]);
  const [trackingLinks, setTrackingLinks] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [detailedEvents, setDetailedEvents] = useState({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('analytics');
  
  // Dialog states
  const [showCreateCampaign, setShowCreateCampaign] = useState(false);
  const [showCreateLink, setShowCreateLink] = useState(false);
  const [showEventDetails, setShowEventDetails] = useState(false);
  const [selectedToken, setSelectedToken] = useState(null);
  
  // Form states
  const [newCampaign, setNewCampaign] = useState({
    name: '',
    description: '',
    status: 'active'
  });
  const [newLink, setNewLink] = useState({
    original_url: '',
    recipient_email: '',
    campaign_name: ''
  });

  useEffect(() => {
    fetchAnalytics();
    fetchCampaigns();
    fetchTrackingLinks();
  }, []);

  const fetchAnalytics = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/tracking/user-analytics', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setAnalytics(data);
      }
    } catch (error) {
      console.error('Error fetching analytics:', error);
    }
  };

  const fetchCampaigns = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/campaigns', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setCampaigns(data.campaigns || []);
      }
    } catch (error) {
      console.error('Error fetching campaigns:', error);
    }
  };

  const fetchTrackingLinks = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/tracking/user-links', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setTrackingLinks(data.links || []);
      }
    } catch (error) {
      console.error('Error fetching tracking links:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchDetailedEvents = async (trackingToken) => {
    try {
      const response = await fetch(`http://localhost:5000/api/tracking/detailed-events/${trackingToken}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setDetailedEvents(prev => ({...prev, [trackingToken]: data}));
      }
    } catch (error) {
      console.error('Error fetching detailed events:', error);
    }
  };

  const createCampaign = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/campaigns', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(newCampaign),
      });

      if (response.ok) {
        toast.success('Campaign created successfully!');
        setShowCreateCampaign(false);
        setNewCampaign({ name: '', description: '', status: 'active' });
        fetchCampaigns();
      } else {
        const error = await response.json();
        toast.error(error.error || 'Failed to create campaign');
      }
    } catch (error) {
      toast.error('Failed to create campaign');
    }
  };

  const createTrackingLink = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/tracking-links', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(newLink),
      });

      if (response.ok) {
        toast.success('Tracking link created successfully!');
        setShowCreateLink(false);
        setNewLink({ original_url: '', recipient_email: '', campaign_name: '' });
        fetchTrackingLinks();
      } else {
        const error = await response.json();
        toast.error(error.error || 'Failed to create tracking link');
      }
    } catch (error) {
      toast.error('Failed to create tracking link');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard!');
  };

  const viewEventDetails = (trackingToken) => {
    setSelectedToken(trackingToken);
    fetchDetailedEvents(trackingToken);
    setShowEventDetails(true);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-purple-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-blue-900 to-indigo-900">
      {/* Header */}
      <div className="bg-white/10 backdrop-blur-md border-b border-white/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <div className="flex items-center space-x-2">
                <Link className="h-8 w-8 text-white" />
                <h1 className="text-2xl font-bold text-white">Brain Link Tracker</h1>
              </div>
              <Badge variant="secondary" className="bg-green-500 text-white">
                <PersonStanding className="h-4 w-4 mr-1" />
                Individual
              </Badge>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-white/80">Welcome, {user.username}</span>
              <Button variant="outline" className="text-white border-white/30 hover:bg-white/10">
                Logout
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white/95 backdrop-blur-sm rounded-lg shadow-xl">
          <div className="p-6">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-3xl font-bold text-gray-900">Individual Analytics Dashboard</h2>
              <div className="flex space-x-2">
                <Button onClick={() => window.location.reload()}>
                  <Activity className="h-4 w-4 mr-2" />
                  Refresh
                </Button>
                <Button variant="outline">
                  <Settings className="h-4 w-4 mr-2" />
                  Export
                </Button>
              </div>
            </div>

            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              <TabsList className="grid w-full grid-cols-5">
                <TabsTrigger value="analytics">Analytics</TabsTrigger>
                <TabsTrigger value="tracking-links">Tracking Links</TabsTrigger>
                <TabsTrigger value="campaigns">Campaign Overview</TabsTrigger>
                <TabsTrigger value="security">Security</TabsTrigger>
                <TabsTrigger value="geography">Geography</TabsTrigger>
              </TabsList>

              {/* Analytics Tab */}
              <TabsContent value="analytics" className="space-y-6">
                {analytics && (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Personal Campaigns</CardTitle>
                        <Target className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.summary?.total_campaigns || 0}</div>
                        <p className="text-xs text-muted-foreground">Your campaigns</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Tracking Links</CardTitle>
                        <Link className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.summary?.total_links || 0}</div>
                        <p className="text-xs text-muted-foreground">All campaigns</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Clicks</CardTitle>
                        <MousePointer className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.summary?.total_clicks || 0}</div>
                        <p className="text-xs text-muted-foreground">All time</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Email Opens</CardTitle>
                        <Mail className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.summary?.total_opens || 0}</div>
                        <p className="text-xs text-muted-foreground">Total opens</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Unique Visitors</CardTitle>
                        <Users className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.summary?.unique_visitors || 0}</div>
                        <p className="text-xs text-muted-foreground">Unique IPs</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Conversion Rate</CardTitle>
                        <TrendingUp className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.summary?.conversion_rate || 0}%</div>
                        <p className="text-xs text-muted-foreground">Click/open ratio</p>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </TabsContent>

              {/* Tracking Links Tab */}
              <TabsContent value="tracking-links" className="space-y-6">
                <Card>
                  <CardHeader>
                    <div className="flex justify-between items-center">
                      <div>
                        <CardTitle className="flex items-center">
                          <Link className="h-5 w-5 mr-2" />
                          Generate New Tracking Link
                        </CardTitle>
                        <CardDescription>Create a new tracking link for your campaign</CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Input
                        placeholder="Enter your campaign URL (e.g., https://example.com...)"
                        value={newLink.original_url}
                        onChange={(e) => setNewLink({...newLink, original_url: e.target.value})}
                      />
                      <Input
                        placeholder="Recipient email (optional)"
                        value={newLink.recipient_email}
                        onChange={(e) => setNewLink({...newLink, recipient_email: e.target.value})}
                      />
                      <Input
                        placeholder="Campaign name (optional)"
                        value={newLink.campaign_name}
                        onChange={(e) => setNewLink({...newLink, campaign_name: e.target.value})}
                      />
                    </div>
                    <div className="mt-4">
                      <Button onClick={createTrackingLink} className="w-full md:w-auto">
                        <Plus className="h-4 w-4 mr-2" />
                        Generate Link
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Link className="h-5 w-5 mr-2" />
                      Your Tracking Links
                    </CardTitle>
                    <CardDescription>Monitor your tracking links and their performance</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Tracking ID</TableHead>
                            <TableHead>Original URL</TableHead>
                            <TableHead>Campaign</TableHead>
                            <TableHead>Email</TableHead>
                            <TableHead>Created</TableHead>
                            <TableHead>Stats</TableHead>
                            <TableHead>Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {trackingLinks.map((link) => (
                            <TableRow key={link.id}>
                              <TableCell className="font-mono text-sm">
                                {link.tracking_token}
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => copyToClipboard(link.tracking_token)}
                                  className="ml-2 h-6 w-6 p-0"
                                >
                                  <Copy className="h-3 w-3" />
                                </Button>
                              </TableCell>
                              <TableCell>
                                <div className="flex items-center space-x-2">
                                  <span className="truncate max-w-xs">{link.original_url}</span>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => window.open(link.original_url, '_blank')}
                                    className="h-6 w-6 p-0"
                                  >
                                    <ExternalLink className="h-3 w-3" />
                                  </Button>
                                </div>
                              </TableCell>
                              <TableCell>{link.campaign_name || 'N/A'}</TableCell>
                              <TableCell>{link.recipient_email || 'N/A'}</TableCell>
                              <TableCell>{new Date(link.created_at).toLocaleDateString()}</TableCell>
                              <TableCell>
                                <div className="text-sm">
                                  <div>Clicks: {link.stats?.clicks || 0}</div>
                                  <div>Opens: {link.stats?.opens || 0}</div>
                                  <div>Unique: {link.stats?.unique_visitors || 0}</div>
                                </div>
                              </TableCell>
                              <TableCell>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => viewEventDetails(link.tracking_token)}
                                >
                                  <Eye className="h-4 w-4 mr-1" />
                                  Details
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Campaign Overview Tab */}
              <TabsContent value="campaigns" className="space-y-6">
                <Card>
                  <CardHeader>
                    <div className="flex justify-between items-center">
                      <div>
                        <CardTitle>Create New Campaign</CardTitle>
                        <CardDescription>Create a new campaign to organize your tracking links</CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="campaign-name">Campaign Name</Label>
                        <Input
                          id="campaign-name"
                          placeholder="Enter campaign name"
                          value={newCampaign.name}
                          onChange={(e) => setNewCampaign({...newCampaign, name: e.target.value})}
                        />
                      </div>
                      <div>
                        <Label htmlFor="campaign-status">Status</Label>
                        <select
                          id="campaign-status"
                          className="w-full px-3 py-2 border border-gray-300 rounded-md"
                          value={newCampaign.status}
                          onChange={(e) => setNewCampaign({...newCampaign, status: e.target.value})}
                        >
                          <option value="active">Active</option>
                          <option value="paused">Paused</option>
                          <option value="completed">Completed</option>
                        </select>
                      </div>
                    </div>
                    <div className="mt-4">
                      <Label htmlFor="campaign-description">Description</Label>
                      <Textarea
                        id="campaign-description"
                        placeholder="Enter campaign description"
                        value={newCampaign.description}
                        onChange={(e) => setNewCampaign({...newCampaign, description: e.target.value})}
                      />
                    </div>
                    <div className="mt-4">
                      <Button onClick={createCampaign} className="w-full md:w-auto">
                        <FolderPlus className="h-4 w-4 mr-2" />
                        Create Campaign
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Your Campaigns</CardTitle>
                    <CardDescription>View and manage your personal campaigns</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Name</TableHead>
                          <TableHead>Description</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Created</TableHead>
                          <TableHead>Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {campaigns.map((campaign) => (
                          <TableRow key={campaign.id}>
                            <TableCell className="font-medium">{campaign.name}</TableCell>
                            <TableCell>{campaign.description}</TableCell>
                            <TableCell>
                              <Badge variant={campaign.status === 'active' ? 'default' : 'secondary'}>
                                {campaign.status}
                              </Badge>
                            </TableCell>
                            <TableCell>{new Date(campaign.created_at).toLocaleDateString()}</TableCell>
                            <TableCell>
                              <div className="flex space-x-2">
                                <Button variant="outline" size="sm">
                                  <Edit className="h-4 w-4" />
                                </Button>
                                <Button variant="outline" size="sm">
                                  <Eye className="h-4 w-4" />
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Security Tab */}
              <TabsContent value="security" className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Shield className="h-5 w-5 mr-2" />
                      Security Overview
                    </CardTitle>
                    <CardDescription>Monitor security events and threats</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="text-center py-8">
                      <Shield className="h-12 w-12 mx-auto text-gray-400 mb-4" />
                      <p className="text-gray-500">Security monitoring data will appear here</p>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Geography Tab */}
              <TabsContent value="geography" className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Globe className="h-5 w-5 mr-2" />
                      Geographic Analytics
                    </CardTitle>
                    <CardDescription>View visitor locations and geographic data</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="text-center py-8">
                      <Globe className="h-12 w-12 mx-auto text-gray-400 mb-4" />
                      <p className="text-gray-500">Geographic data will appear here</p>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </div>

      {/* Event Details Dialog */}
      <Dialog open={showEventDetails} onOpenChange={setShowEventDetails}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>Detailed Event Information</DialogTitle>
            <DialogDescription>
              Comprehensive tracking data for token: {selectedToken}
            </DialogDescription>
          </DialogHeader>
          <div className="max-h-96 overflow-y-auto">
            {selectedToken && detailedEvents[selectedToken] && (
              <div className="space-y-4">
                {detailedEvents[selectedToken].map((event, index) => (
                  <Card key={index}>
                    <CardContent className="pt-4">
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                        <div>
                          <strong>Event Type:</strong> {event.event_type}
                        </div>
                        <div>
                          <strong>IP Address:</strong> {event.ip_address}
                        </div>
                        <div>
                          <strong>Location:</strong> {event.city}, {event.country}
                        </div>
                        <div>
                          <strong>ISP:</strong> {event.isp || 'N/A'}
                        </div>
                        <div>
                          <strong>Device:</strong> {event.device_type}
                        </div>
                        <div>
                          <strong>Browser:</strong> {event.browser}
                        </div>
                        <div>
                          <strong>OS:</strong> {event.os}
                        </div>
                        <div>
                          <strong>Bot Detected:</strong> {event.is_bot ? 'Yes' : 'No'}
                        </div>
                        <div>
                          <strong>Timestamp:</strong> {new Date(event.timestamp).toLocaleString()}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default IndividualDashboard;

