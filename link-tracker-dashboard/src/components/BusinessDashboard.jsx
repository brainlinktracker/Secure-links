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
  UserPlus, Building, Briefcase, PieChart, LineChart
} from 'lucide-react';

const BusinessDashboard = ({ user, token }) => {
  const [campaigns, setCampaigns] = useState([]);
  const [trackingLinks, setTrackingLinks] = useState([]);
  const [workers, setWorkers] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [comprehensiveAnalytics, setComprehensiveAnalytics] = useState(null);
  const [campaignOverview, setCampaignOverview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('analytics');
  
  // Dialog states
  const [showCreateWorker, setShowCreateWorker] = useState(false);
  const [showCreateCampaign, setShowCreateCampaign] = useState(false);
  const [showCreateLink, setShowCreateLink] = useState(false);
  
  // Form states
  const [newWorker, setNewWorker] = useState({
    username: '',
    email: '',
    password: 'worker123'
  });
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
    fetchComprehensiveAnalytics();
    fetchCampaignOverview();
    fetchCampaigns();
    fetchTrackingLinks();
    fetchWorkers();
  }, []);

  const fetchComprehensiveAnalytics = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/business/comprehensive-analytics', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setComprehensiveAnalytics(data);
      }
    } catch (error) {
      console.error('Error fetching comprehensive analytics:', error);
    }
  };

  const fetchCampaignOverview = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/business/campaign-overview', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setCampaignOverview(data);
      }
    } catch (error) {
      console.error('Error fetching campaign overview:', error);
    }
  };

  const fetchAnalytics = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/business/analytics', {
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
      const response = await fetch('http://localhost:5000/api/business/campaigns', {
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

  const fetchWorkers = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/business/workers', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setWorkers(data.workers || []);
      }
    } catch (error) {
      console.error('Error fetching workers:', error);
    }
  };

  const createWorker = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/business/create-worker', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(newWorker),
      });

      if (response.ok) {
        const data = await response.json();
        toast.success(`Worker created successfully! Default password: ${data.default_password}`);
        setShowCreateWorker(false);
        setNewWorker({ username: '', email: '', password: 'worker123' });
        fetchWorkers();
      } else {
        const error = await response.json();
        toast.error(error.error || 'Failed to create worker');
      }
    } catch (error) {
      toast.error('Failed to create worker');
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
              <Badge variant="secondary" className="bg-orange-500 text-white">
                <Building className="h-4 w-4 mr-1" />
                Business
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
              <h2 className="text-3xl font-bold text-gray-900">Business Analytics Dashboard</h2>
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
              <TabsList className="grid w-full grid-cols-6">
                <TabsTrigger value="analytics">Analytics</TabsTrigger>
                <TabsTrigger value="tracking-links">Tracking Links</TabsTrigger>
                <TabsTrigger value="user-management">User Management</TabsTrigger>
                <TabsTrigger value="campaigns">Campaign Overview</TabsTrigger>
                <TabsTrigger value="security">Security</TabsTrigger>
                <TabsTrigger value="geography">Geography</TabsTrigger>
              </TabsList>

              {/* Analytics Tab */}
              <TabsContent value="analytics" className="space-y-6">
                {analytics && (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Campaigns</CardTitle>
                        <Target className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.total_campaigns}</div>
                        <p className="text-xs text-muted-foreground">All campaigns</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Tracking Links</CardTitle>
                        <Link className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.total_links}</div>
                        <p className="text-xs text-muted-foreground">All campaigns</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Clicks</CardTitle>
                        <MousePointer className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.total_clicks}</div>
                        <p className="text-xs text-muted-foreground">All time</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Email Opens</CardTitle>
                        <Mail className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.total_opens}</div>
                        <p className="text-xs text-muted-foreground">Total opens</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Workers</CardTitle>
                        <Users className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.workers_count}</div>
                        <p className="text-xs text-muted-foreground">Active workers</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Conversion Rate</CardTitle>
                        <TrendingUp className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{analytics.conversion_rate}%</div>
                        <p className="text-xs text-muted-foreground">Click/open ratio</p>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </TabsContent>

              {/* Tracking Links Tab */}
              <TabsContent value="tracking-links" className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold">Generate New Tracking Link</h3>
                </div>
                
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Plus className="h-5 w-5 mr-2" />
                      Generate New Tracking Link
                    </CardTitle>
                    <CardDescription>
                      Create a new tracking link for your campaign. Enter your original URL and get a protected tracking link that blocks bots and provides analytics.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <Label htmlFor="url">Enter your campaign URL (e.g., https://example.com)</Label>
                        <Input
                          id="url"
                          placeholder="https://example.com"
                          value={newLink.original_url}
                          onChange={(e) => setNewLink({...newLink, original_url: e.target.value})}
                        />
                      </div>
                      <div>
                        <Label htmlFor="email">Recipient email (optional)</Label>
                        <Input
                          id="email"
                          placeholder="recipient@example.com"
                          value={newLink.recipient_email}
                          onChange={(e) => setNewLink({...newLink, recipient_email: e.target.value})}
                        />
                      </div>
                      <div>
                        <Label htmlFor="campaign">Campaign name (optional)</Label>
                        <Input
                          id="campaign"
                          placeholder="My Campaign"
                          value={newLink.campaign_name}
                          onChange={(e) => setNewLink({...newLink, campaign_name: e.target.value})}
                        />
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      Your tracking link will be protected against bots, social media crawlers, and security scanners.
                    </p>
                    <Button onClick={createTrackingLink} className="w-full">
                      <Plus className="h-4 w-4 mr-2" />
                      Generate Link
                    </Button>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Link className="h-5 w-5 mr-2" />
                      Tracking Links
                    </CardTitle>
                    <CardDescription>Manage and monitor all your tracking links</CardDescription>
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
                            <TableHead>Status</TableHead>
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
                                </div>
                              </TableCell>
                              <TableCell>
                                <Badge variant={link.status === 'active' ? 'default' : 'secondary'}>
                                  {link.status}
                                </Badge>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* User Management Tab */}
              <TabsContent value="user-management" className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold">User Management</h3>
                  <Dialog open={showCreateWorker} onOpenChange={setShowCreateWorker}>
                    <DialogTrigger asChild>
                      <Button>
                        <UserPlus className="h-4 w-4 mr-2" />
                        Create Worker
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Create New Worker</DialogTitle>
                        <DialogDescription>
                          Create a new worker account under your business.
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4">
                        <div>
                          <Label htmlFor="worker-username">Username</Label>
                          <Input
                            id="worker-username"
                            value={newWorker.username}
                            onChange={(e) => setNewWorker({...newWorker, username: e.target.value})}
                          />
                        </div>
                        <div>
                          <Label htmlFor="worker-email">Email</Label>
                          <Input
                            id="worker-email"
                            type="email"
                            value={newWorker.email}
                            onChange={(e) => setNewWorker({...newWorker, email: e.target.value})}
                          />
                        </div>
                        <div>
                          <Label htmlFor="worker-password">Default Password</Label>
                          <Input
                            id="worker-password"
                            value={newWorker.password}
                            onChange={(e) => setNewWorker({...newWorker, password: e.target.value})}
                          />
                        </div>
                        <Button onClick={createWorker} className="w-full">
                          Create Worker
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>

                <Card>
                  <CardHeader>
                    <CardTitle>Workers</CardTitle>
                    <CardDescription>Manage your worker accounts</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Username</TableHead>
                          <TableHead>Email</TableHead>
                          <TableHead>Role</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Last Login</TableHead>
                          <TableHead>Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {workers.map((worker) => (
                          <TableRow key={worker.id}>
                            <TableCell>{worker.username}</TableCell>
                            <TableCell>{worker.email}</TableCell>
                            <TableCell>
                              <Badge variant="outline">{worker.role}</Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant={worker.status === 'active' ? 'default' : 'secondary'}>
                                {worker.status}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {worker.last_login ? new Date(worker.last_login).toLocaleDateString() : 'Never'}
                            </TableCell>
                            <TableCell>
                              <Button variant="outline" size="sm">
                                Edit Role
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Campaign Overview Tab */}
              <TabsContent value="campaigns" className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold">Campaign Management</h3>
                  <Dialog open={showCreateCampaign} onOpenChange={setShowCreateCampaign}>
                    <DialogTrigger asChild>
                      <Button>
                        <Plus className="h-4 w-4 mr-2" />
                        New Campaign
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Create New Campaign</DialogTitle>
                        <DialogDescription>
                          Create a new marketing campaign.
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4">
                        <div>
                          <Label htmlFor="campaign-name">Campaign Name</Label>
                          <Input
                            id="campaign-name"
                            value={newCampaign.name}
                            onChange={(e) => setNewCampaign({...newCampaign, name: e.target.value})}
                          />
                        </div>
                        <div>
                          <Label htmlFor="campaign-description">Description</Label>
                          <Textarea
                            id="campaign-description"
                            value={newCampaign.description}
                            onChange={(e) => setNewCampaign({...newCampaign, description: e.target.value})}
                          />
                        </div>
                        <Button onClick={createCampaign} className="w-full">
                          Create Campaign
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>

                <Card>
                  <CardHeader>
                    <CardTitle>Campaigns</CardTitle>
                    <CardDescription>Manage your marketing campaigns</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Name</TableHead>
                          <TableHead>Description</TableHead>
                          <TableHead>Creator</TableHead>
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
                            <TableCell>{campaign.creator}</TableCell>
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
                      Security Status
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="flex items-center space-x-3">
                        <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                        <div>
                          <p className="font-medium">Authentication</p>
                          <p className="text-sm text-muted-foreground">Secure (Active)</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                        <div>
                          <p className="font-medium">User Sessions</p>
                          <p className="text-sm text-muted-foreground">{workers.length} (Monitored)</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                        <div>
                          <p className="font-medium">Access Control</p>
                          <p className="text-sm text-muted-foreground">Enabled (Protected)</p>
                        </div>
                      </div>
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
                      Geographic Data
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-center py-8">
                      <Globe className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                      <p className="text-muted-foreground">
                        Geographic data will be available when user activity is tracked
                      </p>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BusinessDashboard;

