# 🔧 DNS Configuration for GoDaddy + Render

## Quick Setup Guide

### 1. Render App URL
Your Render app URL: `https://your-app-name.onrender.com`

### 2. Required DNS Records in GoDaddy

#### For Root Domain (yourdomain.com):
```
Type: A
Name: @
Value: 76.76.19.61
TTL: 600
```

#### For WWW Subdomain (www.yourdomain.com):
```
Type: CNAME
Name: www
Value: your-app-name.onrender.com
TTL: 600
```

### 3. GoDaddy DNS Setup Steps

1. **Login to GoDaddy**
   - Go to godaddy.com
   - Sign in to your account

2. **Access DNS Management**
   - Go to "My Products"
   - Find your domain
   - Click "DNS" → "Manage"

3. **Update/Add Records**
   - Find existing A record for `@` → Update to `76.76.19.61`
   - Find existing CNAME record for `www` → Update to `your-app-name.onrender.com`
   - If records don't exist, click "Add" to create them

4. **Save Changes**
   - Click "Save" after updating each record
   - Wait for DNS propagation (5-60 minutes)

### 4. Render Custom Domain Setup

1. **Add Custom Domain in Render**
   - Go to your Render service dashboard
   - Click "Settings" tab
   - Scroll to "Custom Domains"
   - Click "Add Custom Domain"
   - Enter: `yourdomain.com`
   - Click "Add Domain"

2. **Add WWW Domain (Optional)**
   - Add another custom domain: `www.yourdomain.com`
   - This will redirect to your main domain

### 5. Environment Variables in Render

Add these in your Render dashboard under "Environment":

```
CUSTOM_DOMAIN=yourdomain.com
```

### 6. Test Your Setup

1. **Check DNS Propagation**
   - Visit: whatsmydns.net
   - Enter your domain
   - Check if A record points to `76.76.19.61`

2. **Test Your Site**
   - Visit: `https://yourdomain.com`
   - Should load your essay writing service
   - Check for SSL certificate (green lock)

### 7. Common Issues & Solutions

#### Issue: Domain not loading
- **Solution**: Wait 24-48 hours for full DNS propagation
- **Check**: Verify DNS records are correct
- **Test**: Use different DNS servers (8.8.8.8, 1.1.1.1)

#### Issue: SSL certificate not working
- **Solution**: Wait 10-15 minutes after adding custom domain
- **Check**: Ensure domain is properly configured in Render
- **Test**: Try incognito mode

#### Issue: Mixed content warnings
- **Solution**: All resources must use HTTPS
- **Check**: Update any HTTP links to HTTPS
- **Test**: Clear browser cache

### 8. Verification Checklist

- [ ] DNS A record points to `76.76.19.61`
- [ ] DNS CNAME record points to your Render app
- [ ] Custom domain added in Render
- [ ] SSL certificate active
- [ ] Site loads at `https://yourdomain.com`
- [ ] All pages work correctly
- [ ] Admin panel accessible
- [ ] No mixed content warnings

### 9. Timeline

- **DNS Changes**: 5-60 minutes
- **SSL Certificate**: 10-15 minutes
- **Full Propagation**: 24-48 hours
- **Global Access**: Up to 72 hours

## 🎉 Success!

Once DNS propagates, your GoDaddy domain will be live on Render!

**Your site will be available at:**
- `https://yourdomain.com`
- `https://www.yourdomain.com`

**Admin panel:**
- `https://yourdomain.com/admin`
