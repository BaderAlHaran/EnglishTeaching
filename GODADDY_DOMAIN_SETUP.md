# 🌐 GoDaddy Domain Setup with Render

## Overview
This guide will help you connect your GoDaddy domain to your Render deployment.

## Prerequisites
- ✅ GoDaddy domain registered
- ✅ Render app deployed and running
- ✅ Access to GoDaddy DNS management
- ✅ Render service URL (e.g., `https://your-app.onrender.com`)

## Step 1: Get Your Render App URL

1. Go to your Render dashboard
2. Click on your web service
3. Copy the **Service URL** (e.g., `https://essay-writing-service.onrender.com`)

## Step 2: Configure Custom Domain in Render

### 2.1 Add Custom Domain
1. In your Render service dashboard
2. Go to **Settings** tab
3. Scroll down to **Custom Domains**
4. Click **Add Custom Domain**
5. Enter your domain (e.g., `yourdomain.com` or `www.yourdomain.com`)
6. Click **Add Domain**

### 2.2 Get DNS Records
After adding the domain, Render will show you the DNS records you need to configure:
- **Type**: CNAME
- **Name**: `www` (or your subdomain)
- **Value**: `your-app.onrender.com`
- **Type**: A
- **Name**: `@` (for root domain)
- **Value**: `76.76.19.61` (Render's IP)

## Step 3: Configure DNS in GoDaddy

### 3.1 Access GoDaddy DNS Management
1. Log in to your GoDaddy account
2. Go to **My Products**
3. Find your domain and click **DNS**
4. Click **Manage** next to DNS

### 3.2 Add/Update DNS Records

#### For Root Domain (yourdomain.com):
1. Find the **A** record for `@`
2. Update the **Points to** value to: `76.76.19.61`
3. Set **TTL** to: `600` (10 minutes)

#### For WWW Subdomain (www.yourdomain.com):
1. Find the **CNAME** record for `www`
2. Update the **Points to** value to: `your-app.onrender.com`
3. Set **TTL** to: `600` (10 minutes)

#### If Records Don't Exist:
1. Click **Add** to create new records
2. Add the A record for `@` pointing to `76.76.19.61`
3. Add the CNAME record for `www` pointing to `your-app.onrender.com`

### 3.3 Example DNS Configuration
```
Type    Name    Value                    TTL
A       @       76.76.19.61             600
CNAME   www     your-app.onrender.com   600
```

## Step 4: SSL Certificate Setup

### 4.1 Automatic SSL
- Render automatically provides SSL certificates
- No additional configuration needed
- Your site will be available at `https://yourdomain.com`

### 4.2 Verify SSL
- Wait 5-10 minutes after DNS propagation
- Visit `https://yourdomain.com`
- Check for the green lock icon in browser

## Step 5: Update Your App Configuration

### 5.1 Update CORS Settings
Update your `app.py` to include your custom domain:

```python
CORS(app, origins=[
    "https://yourdomain.com",
    "https://www.yourdomain.com",
    "https://*.onrender.com",
    "https://*.render.com", 
    "http://localhost:5000",
    "http://127.0.0.1:5000"
])
```

### 5.2 Update Environment Variables
In Render dashboard, add:
```
CUSTOM_DOMAIN=yourdomain.com
```

## Step 6: Test Your Domain

### 6.1 DNS Propagation Check
1. Use online tools like:
   - `whatsmydns.net`
   - `dnschecker.org`
2. Check if your domain points to Render's IP

### 6.2 Test Your Application
1. Visit `https://yourdomain.com`
2. Test all pages:
   - Home page
   - About page
   - Essay form
   - Admin panel
3. Verify SSL certificate

## Step 7: Optional - Redirect Setup

### 7.1 Redirect HTTP to HTTPS
Add this to your `app.py`:

```python
@app.before_request
def force_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        return redirect(request.url.replace('http://', 'https://'), code=301)
```

### 7.2 Redirect www to non-www (or vice versa)
Configure in Render dashboard under **Custom Domains** settings.

## Troubleshooting

### Common Issues

#### 1. Domain Not Working
- **Check DNS propagation**: Wait 24-48 hours for full propagation
- **Verify DNS records**: Ensure they match Render's requirements
- **Check TTL**: Lower TTL values help with faster updates

#### 2. SSL Certificate Issues
- **Wait for propagation**: SSL setup can take 10-15 minutes
- **Check domain verification**: Ensure domain is properly configured
- **Clear browser cache**: Try incognito mode

#### 3. Mixed Content Issues
- **Update all URLs**: Ensure all internal links use HTTPS
- **Check external resources**: Update any HTTP resources to HTTPS

### DNS Propagation Timeline
- **Local changes**: 5-10 minutes
- **Global propagation**: 24-48 hours
- **Full propagation**: Up to 72 hours

## Final Verification Checklist

- [ ] DNS records configured correctly
- [ ] Domain added to Render
- [ ] SSL certificate active
- [ ] Site loads at `https://yourdomain.com`
- [ ] All pages work correctly
- [ ] Admin panel accessible
- [ ] Forms submit successfully
- [ ] File uploads work
- [ ] No mixed content warnings

## Support Resources

### GoDaddy Support
- **Phone**: 1-480-505-8877
- **Live Chat**: Available 24/7
- **Help Center**: help.godaddy.com

### Render Support
- **Documentation**: render.com/docs
- **Community**: community.render.com
- **Support**: support@render.com

## 🎉 Success!

Your GoDaddy domain is now connected to your Render deployment!

**Your site is live at:**
- `https://yourdomain.com`
- `https://www.yourdomain.com`

**Admin panel:**
- `https://yourdomain.com/admin`

Remember to:
- Monitor DNS propagation
- Test all functionality
- Keep SSL certificate updated
- Monitor site performance
