import React, { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './ui/dialog';
import { Label } from './ui/label';
import { toast } from 'sonner';
import { 
  Briefcase, Plus, Eye, BarChart3, TrendingUp, Activity, 
  Link, Mail, Calendar, Globe, Copy, ExternalLink, Settings,
  Target, Users, MousePointer, Shield
} from 'lucide-react';

const MemberDashboard = ({ user, token }) => {
  const [campaigns, setCampaigns] = useState([]);
  const [trackingLinks, setTrackingLinks] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [newCampaign, setNewCampaign] = useState({ name: '', description: '' });
  const [newLink, setNewLink] = useState({ 
    original_url: '', 
    recipient_email: '', 
    campaign_id: '',
    custom_alias: ''
  });
  const [showNewCampaign, setShowNewCampaign] = useState(false);
  const [showNewLink, setShowNewLink] = useState(false);

  useEffect(() => {
    fetchCampaigns();
    fetchTrackingLinks();
    fetchAnalytics();
  }, []);

  const fetchCampaigns = async () => {
    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/campaigns', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setCampaigns(data.campaigns || []);
      } else {
        toast.error('Failed to fetch campaigns');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const fetchTrackingLinks = async () => {
    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/tracking-links', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setTrackingLinks(data.links || []);
      } else {
        toast.error('Failed to fetch tracking links');
      }
    } catch (error) {
      toast.error('Network error');
    } finally {
      setLoading(false);
    }
  };

  const fetchAnalytics = async () => {
    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/analytics', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setAnalytics(data);
      }
    } catch (error) {
      console.error('Failed to fetch analytics:', error);
    }
  };

  const createCampaign = async () => {
    if (!newCampaign.name.trim()) {
      toast.error('Campaign name is required');
      return;
    }

    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/campaigns', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newCampaign),
      });

      if (response.ok) {
        toast.success('Campaign created successfully');
        setNewCampaign({ name: '', description: '' });
        setShowNewCampaign(false);
        fetchCampaigns();
      } else {
        toast.error('Failed to create campaign');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const createTrackingLink = async () => {
    if (!newLink.original_url.trim() || !newLink.campaign_id) {
      toast.error('URL and campaign are required');
      return;
    }

    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/tracking-links', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newLink),
      });

      if (response.ok) {
        const data = await response.json();
        toast.success('Tracking link created successfully');
        setNewLink({ original_url: '', recipient_email: '', campaign_id: '', custom_alias: '' });
        setShowNewLink(false);
        fetchTrackingLinks();
      } else {
        toast.error('Failed to create tracking link');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const getStatusBadgeColor = (status) => {
    switch (status) {
      case 'sent': return 'bg-blue-500';
      case 'clicked': return 'bg-green-500';
      case 'opened': return 'bg-yellow-500';
      case 'redirected': return 'bg-purple-500';
      case 'ok': return 'bg-green-600';
      default: return 'bg-gray-500';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'sent': return <Mail className="h-3 w-3" />;
      case 'clicked': return <MousePointer className="h-3 w-3" />;
      case 'opened': return <Eye className="h-3 w-3" />;
      case 'redirected': return <ExternalLink className="h-3 w-3" />;
      case 'ok': return <Target className="h-3 w-3" />;
      default: return <Activity className="h-3 w-3" />;
    }
  };

  // Calculate campaign statistics
  const getCampaignStats = (campaignId) => {
    const campaignLinks = trackingLinks.filter(link => link.campaign_id === campaignId);
    const totalLinks = campaignLinks.length;
    const activeLinks = campaignLinks.filter(link => link.status === 'active').length;
    const totalClicks = campaignLinks.reduce((sum, link) => sum + (link.clicks || 0), 0);
    const totalOpens = campaignLinks.reduce((sum, link) => sum + (link.opens || 0), 0);
    
    return { totalLinks, activeLinks, totalClicks, totalOpens };
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Member Dashboard</h2>
          <p className="text-muted-foreground">Manage your campaigns and tracking links</p>
        </div>
        <Badge className="bg-blue-500 text-white">
          <Briefcase className="h-3 w-3 mr-1" />
          Member - Business Account
        </Badge>
      </div>

      {/* Overview Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Target className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-sm font-medium">Active Campaigns</p>
                <p className="text-2xl font-bold">{campaigns.length}</p>
                <p className="text-xs text-gray-500">Total campaigns</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Link className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-sm font-medium">Tracking Links</p>
                <p className="text-2xl font-bold">{trackingLinks.length}</p>
                <p className="text-xs text-gray-500">Total links created</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <TrendingUp className="h-5 w-5 text-purple-500" />
              <div>
                <p className="text-sm font-medium">Total Clicks</p>
                <p className="text-2xl font-bold">
                  {trackingLinks.reduce((sum, link) => sum + (link.clicks || 0), 0)}
                </p>
                <p className="text-xs text-gray-500">All campaigns</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Activity className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-sm font-medium">Email Opens</p>
                <p className="text-2xl font-bold">
                  {trackingLinks.reduce((sum, link) => sum + (link.opens || 0), 0)}
                </p>
                <p className="text-xs text-gray-500">Total opens</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Campaign Management */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Target className="h-5 w-5" />
                <span>My Campaigns</span>
              </CardTitle>
              <CardDescription>
                Manage your marketing campaigns and track performance
              </CardDescription>
            </div>
            <Dialog open={showNewCampaign} onOpenChange={setShowNewCampaign}>
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
                    Set up a new marketing campaign to organize your tracking links
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="campaign-name">Campaign Name</Label>
                    <input
                      id="campaign-name"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., Summer Sale 2024"
                      value={newCampaign.name}
                      onChange={(e) => setNewCampaign({ ...newCampaign, name: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="campaign-description">Description (Optional)</Label>
                    <textarea
                      id="campaign-description"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Brief description of your campaign"
                      rows={3}
                      value={newCampaign.description}
                      onChange={(e) => setNewCampaign({ ...newCampaign, description: e.target.value })}
                    />
                  </div>
                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" onClick={() => setShowNewCampaign(false)}>
                      Cancel
                    </Button>
                    <Button onClick={createCampaign}>
                      Create Campaign
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          {campaigns.length === 0 ? (
            <div className="text-center py-8">
              <Target className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500">No campaigns yet. Create your first campaign to get started!</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {campaigns.map((campaign) => {
                const stats = getCampaignStats(campaign.id);
                return (
                  <Card key={campaign.id} className="border-l-4 border-l-blue-500">
                    <CardContent className="p-4">
                      <div className="space-y-3">
                        <div>
                          <h4 className="font-semibold">{campaign.name}</h4>
                          <p className="text-sm text-gray-500">{campaign.description || 'No description'}</p>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-sm">
                          <div>
                            <span className="text-gray-500">Links:</span>
                            <span className="ml-1 font-medium">{stats.totalLinks}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Clicks:</span>
                            <span className="ml-1 font-medium">{stats.totalClicks}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Active:</span>
                            <span className="ml-1 font-medium">{stats.activeLinks}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Opens:</span>
                            <span className="ml-1 font-medium">{stats.totalOpens}</span>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <Badge variant="outline">
                            {new Date(campaign.created_at).toLocaleDateString()}
                          </Badge>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setSelectedCampaign(campaign)}
                          >
                            <Eye className="h-3 w-3 mr-1" />
                            View
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Tracking Links Management */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Link className="h-5 w-5" />
                <span>My Tracking Links</span>
              </CardTitle>
              <CardDescription>
                Create and manage tracking links for your campaigns
              </CardDescription>
            </div>
            <Dialog open={showNewLink} onOpenChange={setShowNewLink}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Link
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create Tracking Link</DialogTitle>
                  <DialogDescription>
                    Generate a new tracking link for your campaign
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="original-url">Original URL</Label>
                    <input
                      id="original-url"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="https://example.com/landing-page"
                      value={newLink.original_url}
                      onChange={(e) => setNewLink({ ...newLink, original_url: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="campaign-select">Campaign</Label>
                    <select
                      id="campaign-select"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      value={newLink.campaign_id}
                      onChange={(e) => setNewLink({ ...newLink, campaign_id: e.target.value })}
                    >
                      <option value="">Select a campaign</option>
                      {campaigns.map((campaign) => (
                        <option key={campaign.id} value={campaign.id}>
                          {campaign.name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="recipient-email">Recipient Email (Optional)</Label>
                    <input
                      id="recipient-email"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="recipient@example.com"
                      value={newLink.recipient_email}
                      onChange={(e) => setNewLink({ ...newLink, recipient_email: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="custom-alias">Custom Alias (Optional)</Label>
                    <input
                      id="custom-alias"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="summer-sale-2024"
                      value={newLink.custom_alias}
                      onChange={(e) => setNewLink({ ...newLink, custom_alias: e.target.value })}
                    />
                  </div>
                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" onClick={() => setShowNewLink(false)}>
                      Cancel
                    </Button>
                    <Button onClick={createTrackingLink}>
                      Create Link
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          {trackingLinks.length === 0 ? (
            <div className="text-center py-8">
              <Link className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500">No tracking links yet. Create your first link to start tracking!</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Campaign</TableHead>
                  <TableHead>Original URL</TableHead>
                  <TableHead>Tracking Link</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Clicks</TableHead>
                  <TableHead>Opens</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {trackingLinks.map((link) => {
                  const campaign = campaigns.find(c => c.id === link.campaign_id);
                  const trackingUrl = `https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/track/click/${link.tracking_token}`;
                  
                  return (
                    <TableRow key={link.id}>
                      <TableCell>
                        <Badge variant="outline">
                          {campaign ? campaign.name : 'Unknown'}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs truncate">
                        <a 
                          href={link.original_url} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:underline"
                        >
                          {link.original_url}
                        </a>
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <div className="flex items-center space-x-2">
                          <span className="truncate text-sm font-mono">
                            {trackingUrl}
                          </span>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => copyToClipboard(trackingUrl)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getStatusBadgeColor(link.link_status)} text-white`}>
                          <div className="flex items-center space-x-1">
                            {getStatusIcon(link.link_status)}
                            <span className="capitalize">{link.link_status}</span>
                          </div>
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="font-medium">{link.clicks || 0}</span>
                      </TableCell>
                      <TableCell>
                        <span className="font-medium">{link.opens || 0}</span>
                      </TableCell>
                      <TableCell>
                        {new Date(link.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => copyToClipboard(trackingUrl)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => window.open(link.original_url, '_blank')}
                          >
                            <ExternalLink className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Member Access Notice */}
      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="p-4">
          <div className="flex items-start space-x-3">
            <Briefcase className="h-5 w-5 text-blue-600 mt-0.5" />
            <div>
              <h4 className="font-medium text-blue-800">Member Account Features</h4>
              <p className="text-sm text-blue-700 mt-1">
                As a Member, you have full access to campaign and link management:
              </p>
              <ul className="text-sm text-blue-700 mt-2 space-y-1">
                <li>• Create and manage unlimited campaigns</li>
                <li>• Generate tracking links with advanced analytics</li>
                <li>• Monitor real-time performance metrics</li>
                <li>• Access detailed click and open tracking</li>
                <li>• Export campaign data and reports</li>
                <li>• Manage team workers (if applicable)</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default MemberDashboard;

