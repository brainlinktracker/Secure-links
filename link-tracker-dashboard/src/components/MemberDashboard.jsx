import React, { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './ui/dialog';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Textarea } from './ui/textarea';
import { toast } from 'sonner';
import { 
  User, Plus, Eye, BarChart3, TrendingUp, Activity, 
  Link, Mail, Calendar, Globe, Copy, ExternalLink,
  Target, Users, MousePointer, Shield, AlertCircle,
  FolderPlus, Settings, Trash2, Edit, Play, Pause
} from 'lucide-react';

const MemberDashboard = ({ user, token }) => {
  const [campaigns, setCampaigns] = useState([]);
  const [trackingLinks, setTrackingLinks] = useState([]);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showCreateCampaign, setShowCreateCampaign] = useState(false);
  const [showCreateLink, setShowCreateLink] = useState(false);
  const [newCampaign, setNewCampaign] = useState({
    name: '',
    description: '',
    target_url: '',
    status: 'active'
  });
  const [newLink, setNewLink] = useState({
    original_url: '',
    email: '',
    campaign_id: ''
  });

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

  const fetchTrackingLinks = async (campaignId = null) => {
    try {
      const url = campaignId 
        ? `https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/campaigns/${campaignId}/tracking-links`
        : 'https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/tracking-links';
        
      const response = await fetch(url, {
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
    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/campaigns', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(newCampaign),
      });

      if (response.ok) {
        toast.success('Campaign created successfully');
        setShowCreateCampaign(false);
        setNewCampaign({ name: '', description: '', target_url: '', status: 'active' });
        fetchCampaigns();
      } else {
        const error = await response.json();
        toast.error(error.error || 'Failed to create campaign');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const createTrackingLink = async () => {
    try {
      const response = await fetch('https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/tracking-links', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(newLink),
      });

      if (response.ok) {
        const data = await response.json();
        toast.success('Tracking link created successfully');
        setShowCreateLink(false);
        setNewLink({ original_url: '', email: '', campaign_id: '' });
        fetchTrackingLinks(selectedCampaign?.id);
      } else {
        const error = await response.json();
        toast.error(error.error || 'Failed to create tracking link');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const toggleCampaignStatus = async (campaignId, currentStatus) => {
    try {
      const newStatus = currentStatus === 'active' ? 'paused' : 'active';
      const response = await fetch(`https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/campaigns/${campaignId}/status`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ status: newStatus }),
      });

      if (response.ok) {
        toast.success(`Campaign ${newStatus === 'active' ? 'activated' : 'paused'}`);
        fetchCampaigns();
      } else {
        toast.error('Failed to update campaign status');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const deleteCampaign = async (campaignId) => {
    if (!confirm('Are you sure you want to delete this campaign? This will also delete all associated tracking links.')) {
      return;
    }

    try {
      const response = await fetch(`https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/campaigns/${campaignId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        toast.success('Campaign deleted successfully');
        fetchCampaigns();
        if (selectedCampaign?.id === campaignId) {
          setSelectedCampaign(null);
          fetchTrackingLinks();
        }
      } else {
        toast.error('Failed to delete campaign');
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
      case 'blocked': return 'bg-red-500';
      case 'error': return 'bg-red-600';
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
      case 'blocked': return <Shield className="h-3 w-3" />;
      case 'error': return <AlertCircle className="h-3 w-3" />;
      default: return <Activity className="h-3 w-3" />;
    }
  };

  // Calculate member-specific statistics
  const memberStats = {
    totalCampaigns: campaigns.length,
    activeCampaigns: campaigns.filter(c => c.status === 'active').length,
    totalLinks: trackingLinks.length,
    totalClicks: trackingLinks.reduce((sum, link) => sum + (link.clicks || 0), 0),
    totalOpens: trackingLinks.reduce((sum, link) => sum + (link.opens || 0), 0)
  };

  // Filter links by selected campaign
  const filteredLinks = selectedCampaign 
    ? trackingLinks.filter(link => link.campaign_id === selectedCampaign.id)
    : trackingLinks;

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
          <User className="h-3 w-3 mr-1" />
          Member - Full Access
        </Badge>
      </div>

      {/* Overview Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Target className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-sm font-medium">Total Campaigns</p>
                <p className="text-2xl font-bold">{memberStats.totalCampaigns}</p>
                <p className="text-xs text-gray-500">{memberStats.activeCampaigns} active</p>
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
                <p className="text-2xl font-bold">{memberStats.totalLinks}</p>
                <p className="text-xs text-gray-500">All campaigns</p>
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
                <p className="text-2xl font-bold">{memberStats.totalClicks}</p>
                <p className="text-xs text-gray-500">All time</p>
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
                <p className="text-2xl font-bold">{memberStats.totalOpens}</p>
                <p className="text-xs text-gray-500">Total opens</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <BarChart3 className="h-5 w-5 text-red-500" />
              <div>
                <p className="text-sm font-medium">Conversion Rate</p>
                <p className="text-2xl font-bold">
                  {memberStats.totalOpens > 0 ? ((memberStats.totalClicks / memberStats.totalOpens) * 100).toFixed(1) : 0}%
                </p>
                <p className="text-xs text-gray-500">Click/Open ratio</p>
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
                <span>Campaign Management</span>
              </CardTitle>
              <CardDescription>
                Create and manage your marketing campaigns
              </CardDescription>
            </div>
            <Dialog open={showCreateCampaign} onOpenChange={setShowCreateCampaign}>
              <DialogTrigger asChild>
                <Button>
                  <FolderPlus className="h-4 w-4 mr-2" />
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
                  <div>
                    <Label htmlFor="campaign-name">Campaign Name</Label>
                    <Input
                      id="campaign-name"
                      value={newCampaign.name}
                      onChange={(e) => setNewCampaign({...newCampaign, name: e.target.value})}
                      placeholder="e.g., Summer Sale 2024"
                    />
                  </div>
                  <div>
                    <Label htmlFor="campaign-description">Description</Label>
                    <Textarea
                      id="campaign-description"
                      value={newCampaign.description}
                      onChange={(e) => setNewCampaign({...newCampaign, description: e.target.value})}
                      placeholder="Brief description of the campaign"
                    />
                  </div>
                  <div>
                    <Label htmlFor="campaign-url">Target URL (Optional)</Label>
                    <Input
                      id="campaign-url"
                      value={newCampaign.target_url}
                      onChange={(e) => setNewCampaign({...newCampaign, target_url: e.target.value})}
                      placeholder="https://example.com/landing-page"
                    />
                  </div>
                  <Button onClick={createCampaign} className="w-full">
                    Create Campaign
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          {campaigns.length === 0 ? (
            <div className="text-center py-8">
              <Target className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500">No campaigns yet. Create your first campaign to get started.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {campaigns.map((campaign) => {
                const campaignLinks = trackingLinks.filter(link => link.campaign_id === campaign.id);
                const campaignClicks = campaignLinks.reduce((sum, link) => sum + (link.clicks || 0), 0);
                const campaignOpens = campaignLinks.reduce((sum, link) => sum + (link.opens || 0), 0);
                
                return (
                  <Card 
                    key={campaign.id} 
                    className={`cursor-pointer transition-all ${
                      selectedCampaign?.id === campaign.id 
                        ? 'border-blue-500 bg-blue-50' 
                        : 'hover:shadow-md'
                    }`}
                    onClick={() => {
                      setSelectedCampaign(campaign);
                      fetchTrackingLinks(campaign.id);
                    }}
                  >
                    <CardContent className="p-4">
                      <div className="space-y-3">
                        <div className="flex items-start justify-between">
                          <div>
                            <h4 className="font-semibold">{campaign.name}</h4>
                            <p className="text-sm text-gray-500">{campaign.description || 'No description'}</p>
                          </div>
                          <Badge 
                            variant="outline" 
                            className={campaign.status === 'active' ? 'text-green-600' : 'text-gray-600'}
                          >
                            {campaign.status}
                          </Badge>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-sm">
                          <div>
                            <span className="text-gray-500">Links:</span>
                            <span className="ml-1 font-medium">{campaignLinks.length}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Clicks:</span>
                            <span className="ml-1 font-medium">{campaignClicks}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Opens:</span>
                            <span className="ml-1 font-medium">{campaignOpens}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Rate:</span>
                            <span className="ml-1 font-medium">
                              {campaignOpens > 0 ? ((campaignClicks / campaignOpens) * 100).toFixed(1) : 0}%
                            </span>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <Badge variant="outline">
                            {new Date(campaign.created_at).toLocaleDateString()}
                          </Badge>
                          <div className="flex space-x-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleCampaignStatus(campaign.id, campaign.status);
                              }}
                            >
                              {campaign.status === 'active' ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={(e) => {
                                e.stopPropagation();
                                deleteCampaign(campaign.id);
                              }}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
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
                <span>
                  Tracking Links 
                  {selectedCampaign && ` - ${selectedCampaign.name}`}
                </span>
              </CardTitle>
              <CardDescription>
                {selectedCampaign 
                  ? `Manage tracking links for ${selectedCampaign.name}` 
                  : 'All tracking links across campaigns'
                }
              </CardDescription>
            </div>
            <div className="flex space-x-2">
              {selectedCampaign && (
                <Button
                  variant="outline"
                  onClick={() => {
                    setSelectedCampaign(null);
                    fetchTrackingLinks();
                  }}
                >
                  View All Links
                </Button>
              )}
              <Dialog open={showCreateLink} onOpenChange={setShowCreateLink}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    New Link
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
                    <div>
                      <Label htmlFor="link-url">Original URL</Label>
                      <Input
                        id="link-url"
                        value={newLink.original_url}
                        onChange={(e) => setNewLink({...newLink, original_url: e.target.value})}
                        placeholder="https://example.com/page"
                      />
                    </div>
                    <div>
                      <Label htmlFor="link-email">Recipient Email (Optional)</Label>
                      <Input
                        id="link-email"
                        value={newLink.email}
                        onChange={(e) => setNewLink({...newLink, email: e.target.value})}
                        placeholder="recipient@example.com"
                      />
                    </div>
                    <div>
                      <Label htmlFor="link-campaign">Campaign</Label>
                      <select
                        id="link-campaign"
                        value={newLink.campaign_id}
                        onChange={(e) => setNewLink({...newLink, campaign_id: e.target.value})}
                        className="w-full p-2 border rounded"
                      >
                        <option value="">Select Campaign</option>
                        {campaigns.map(campaign => (
                          <option key={campaign.id} value={campaign.id}>
                            {campaign.name}
                          </option>
                        ))}
                      </select>
                    </div>
                    <Button onClick={createTrackingLink} className="w-full">
                      Generate Tracking Link
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filteredLinks.length === 0 ? (
            <div className="text-center py-8">
              <Link className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500">
                {selectedCampaign 
                  ? `No tracking links in ${selectedCampaign.name} yet.`
                  : 'No tracking links created yet.'
                } Create your first link to get started.
              </p>
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
                {filteredLinks.map((link) => {
                  const campaign = campaigns.find(c => c.id === link.campaign_id);
                  const trackingUrl = `https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/track/click/${link.tracking_token}`;
                  const pixelUrl = `https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/track/pixel/${link.tracking_token}`;
                  
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
                            title="Copy tracking link"
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => copyToClipboard(pixelUrl)}
                            title="Copy pixel URL"
                          >
                            <Eye className="h-3 w-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => window.open(link.original_url, '_blank')}
                            title="Open original URL"
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

      {/* Member Access Information */}
      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="p-4">
          <div className="flex items-start space-x-3">
            <User className="h-5 w-5 text-blue-600 mt-0.5" />
            <div>
              <h4 className="font-medium text-blue-800">Member Access Level</h4>
              <p className="text-sm text-blue-700 mt-1">
                As a Member, you have full access to campaign and link management:
              </p>
              <ul className="text-sm text-blue-700 mt-2 space-y-1">
                <li>• Create and manage unlimited campaigns</li>
                <li>• Generate unlimited tracking links</li>
                <li>• View detailed analytics and performance metrics</li>
                <li>• Organize links by campaigns for better management</li>
                <li>• Access to advanced tracking status reporting</li>
                <li>• Export data and manage campaign settings</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default MemberDashboard;

