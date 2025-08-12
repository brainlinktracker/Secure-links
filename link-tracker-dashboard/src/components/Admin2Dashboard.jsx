import React, { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './ui/dialog';
import { Label } from './ui/label';
import { toast } from 'sonner';
import { API_ENDPOINTS } from '../config';
import { 
  Users, UserCheck, UserX, Shield, Briefcase, HardHat, 
  TrendingUp, Activity, BarChart3, Eye, Settings 
} from 'lucide-react';

const Admin2Dashboard = ({ user, token }) => {
  const [users, setUsers] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState(null);
  const [newRole, setNewRole] = useState('');

  useEffect(() => {
    fetchUsers();
    fetchAnalytics();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await fetch(API_ENDPOINTS.USERS, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setUsers(data);
      } else {
        toast.error('Failed to fetch users');
      }
    } catch (error) {
      toast.error('Network error');
    } finally {
      setLoading(false);
    }
  };

  const fetchAnalytics = async () => {
    try {
      const response = await fetch(API_ENDPOINTS.ANALYTICS, {
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

  const approveUser = async (userId) => {
    try {
      const response = await fetch(`${API_ENDPOINTS.USERS}/${userId}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        toast.success('User approved successfully');
        fetchUsers();
      } else {
        toast.error('Failed to approve user');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const updateUserRole = async (userId, role) => {
    try {
      const response = await fetch(`https://5000-i3axerqweb415mh7wgsgs-15aa9b1c.manus.computer/api/admin/users/${userId}/role`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ role }),
      });

      if (response.ok) {
        toast.success('User role updated successfully');
        fetchUsers();
        setSelectedUser(null);
      } else {
        toast.error('Failed to update user role');
      }
    } catch (error) {
      toast.error('Network error');
    }
  };

  const getRoleIcon = (role) => {
    switch (role) {
      case 'member': return <Briefcase className="h-4 w-4" />;
      case 'worker': return <HardHat className="h-4 w-4" />;
      default: return <Users className="h-4 w-4" />;
    }
  };

  const getRoleBadgeColor = (role) => {
    switch (role) {
      case 'member': return 'bg-blue-500';
      case 'worker': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusBadgeColor = (status) => {
    switch (status) {
      case 'active': return 'bg-green-500';
      case 'pending': return 'bg-yellow-500';
      case 'inactive': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  // Filter users to only show those in Admin2's hierarchy
  const myUsers = users.filter(u => u.parent_id === user.id || u.id === user.id);
  const pendingUsers = myUsers.filter(u => u.status === 'pending');
  const activeUsers = myUsers.filter(u => u.status === 'active');
  const members = myUsers.filter(u => u.role === 'member');
  const workers = myUsers.filter(u => u.role === 'worker');

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
          <h2 className="text-2xl font-bold">Business Management Dashboard</h2>
          <p className="text-muted-foreground">Manage your team and monitor performance</p>
        </div>
        <Badge className="bg-orange-500 text-white">
          <Shield className="h-3 w-3 mr-1" />
          Admin 2 - Business Manager
        </Badge>
      </div>

      {/* Overview Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Users className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-sm font-medium">Total Team Members</p>
                <p className="text-2xl font-bold">{myUsers.length - 1}</p>
                <p className="text-xs text-gray-500">Excluding yourself</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Briefcase className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-sm font-medium">Members</p>
                <p className="text-2xl font-bold">{members.length}</p>
                <p className="text-xs text-gray-500">Business accounts</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <HardHat className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-sm font-medium">Workers</p>
                <p className="text-2xl font-bold">{workers.length}</p>
                <p className="text-xs text-gray-500">Employee accounts</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <UserX className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="text-sm font-medium">Pending Approval</p>
                <p className="text-2xl font-bold">{pendingUsers.length}</p>
                <p className="text-xs text-gray-500">Awaiting activation</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Performance Analytics */}
      {analytics && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <TrendingUp className="h-5 w-5 text-blue-500" />
                <div>
                  <p className="text-sm font-medium">Team Total Clicks</p>
                  <p className="text-2xl font-bold">{analytics.overview.totalClicks}</p>
                  <p className="text-xs text-green-600">All team campaigns</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <Activity className="h-5 w-5 text-green-500" />
                <div>
                  <p className="text-sm font-medium">Team Conversion Rate</p>
                  <p className="text-2xl font-bold">{analytics.overview.conversionRate}%</p>
                  <p className="text-xs text-green-600">Average performance</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <Shield className="h-5 w-5 text-red-500" />
                <div>
                  <p className="text-sm font-medium">Security Events</p>
                  <p className="text-2xl font-bold">{analytics.overview.blockedRequests}</p>
                  <p className="text-xs text-red-600">Blocked threats</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Pending Approvals */}
      {pendingUsers.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <UserX className="h-5 w-5" />
              <span>Pending Team Member Approvals</span>
            </CardTitle>
            <CardDescription>
              New team members waiting for activation
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Username</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Requested Role</TableHead>
                  <TableHead>Registered</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pendingUsers.map((userItem) => (
                  <TableRow key={userItem.id}>
                    <TableCell className="font-medium">{userItem.username}</TableCell>
                    <TableCell>{userItem.email}</TableCell>
                    <TableCell>
                      <Badge className={`${getRoleBadgeColor(userItem.role)} text-white`}>
                        <div className="flex items-center space-x-1">
                          {getRoleIcon(userItem.role)}
                          <span className="capitalize">{userItem.role}</span>
                        </div>
                      </Badge>
                    </TableCell>
                    <TableCell>{new Date(userItem.created_at).toLocaleDateString()}</TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        onClick={() => approveUser(userItem.id)}
                        className="bg-green-600 hover:bg-green-700"
                      >
                        Approve
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Team Members Management */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Users className="h-5 w-5" />
            <span>My Team Members</span>
          </CardTitle>
          <CardDescription>
            Manage roles and permissions for your team (Limited Admin 2 access)
          </CardDescription>
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
                <TableHead>Subscription</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {myUsers.map((userItem) => (
                <TableRow key={userItem.id}>
                  <TableCell className="font-medium">{userItem.username}</TableCell>
                  <TableCell>{userItem.email}</TableCell>
                  <TableCell>
                    <Badge className={`${getRoleBadgeColor(userItem.role)} text-white`}>
                      <div className="flex items-center space-x-1">
                        {getRoleIcon(userItem.role)}
                        <span className="capitalize">{userItem.role}</span>
                      </div>
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge className={`${getStatusBadgeColor(userItem.status)} text-white`}>
                      {userItem.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {userItem.last_login ? new Date(userItem.last_login).toLocaleDateString() : 'Never'}
                  </TableCell>
                  <TableCell>
                    <Badge variant={userItem.subscription_status === 'active' ? 'default' : 'secondary'}>
                      {userItem.subscription_status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {userItem.id !== user.id && userItem.role !== 'admin' && (
                      <Dialog>
                        <DialogTrigger asChild>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setSelectedUser(userItem);
                              setNewRole(userItem.role);
                            }}
                          >
                            <Settings className="h-3 w-3 mr-1" />
                            Manage
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>Manage Team Member</DialogTitle>
                            <DialogDescription>
                              Update role for {selectedUser?.username} (Admin 2 restrictions apply)
                            </DialogDescription>
                          </DialogHeader>
                          <div className="space-y-4">
                            <div className="space-y-2">
                              <Label htmlFor="role">Role</Label>
                              <select
                                id="role"
                                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                value={newRole}
                                onChange={(e) => setNewRole(e.target.value)}
                              >
                                <option value="member">Member (Business Account)</option>
                                <option value="worker">Worker (Employee)</option>
                              </select>
                              <p className="text-xs text-gray-500">
                                Note: As Admin 2, you can only manage Members and Workers in your team
                              </p>
                            </div>
                            <div className="flex justify-end space-x-2">
                              <Button
                                variant="outline"
                                onClick={() => setSelectedUser(null)}
                              >
                                Cancel
                              </Button>
                              <Button
                                onClick={() => updateUserRole(selectedUser.id, newRole)}
                              >
                                Update Role
                              </Button>
                            </div>
                          </div>
                        </DialogContent>
                      </Dialog>
                    )}
                    {userItem.id === user.id && (
                      <Badge variant="outline">You</Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Restrictions Notice */}
      <Card className="border-orange-200 bg-orange-50">
        <CardContent className="p-4">
          <div className="flex items-start space-x-3">
            <Shield className="h-5 w-5 text-orange-600 mt-0.5" />
            <div>
              <h4 className="font-medium text-orange-800">Admin 2 Access Restrictions</h4>
              <p className="text-sm text-orange-700 mt-1">
                As a Business Manager (Admin 2), you have limited administrative access:
              </p>
              <ul className="text-sm text-orange-700 mt-2 space-y-1">
                <li>• Can only manage users in your team hierarchy</li>
                <li>• Cannot create or manage other Admin 2 accounts</li>
                <li>• Cannot modify system settings or core configurations</li>
                <li>• Can approve and manage Members and Workers only</li>
                <li>• Full access to team analytics and performance data</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Admin2Dashboard;

