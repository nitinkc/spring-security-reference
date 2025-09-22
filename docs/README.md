# MkDocs Documentation Setup

This directory contains the MkDocs configuration and documentation source files for the Spring Security Reference Project.

## 🚀 Quick Start

### 1. Install MkDocs

```bash
# Install Python dependencies
pip install -r requirements.txt

# Or install individually
pip install mkdocs-material
```

### 2. Serve Documentation Locally

```bash
# Start development server
python -m mkdocs serve

# Open browser to http://localhost:8000
```

### 3. Build Static Site

```bash
# Build static site
python -m mkdocs build

# Output will be in site/ directory
```

## 📁 Documentation Structure

```
docs/
├── index.md                    # Homepage
├── getting-started/
│   ├── overview.md            # Project overview
│   ├── quick-setup.md         # Installation guide
│   └── project-structure.md   # Codebase structure
├── authentication/
│   ├── index.md               # Auth methods overview
│   ├── jdbc-auth.md           # Database authentication
│   ├── ldap-auth.md           # Directory authentication
│   ├── oauth2-auth.md         # OAuth2/OIDC authentication
│   └── jwt-tokens.md          # JWT token handling
├── security/
│   ├── index.md               # Security configuration
│   ├── common-security.md     # Shared security config
│   ├── filter-chain.md        # Security filter chain
│   └── authorization.md       # Role-based access
├── api/
│   ├── index.md               # API reference
│   ├── rest-endpoints.md      # REST API documentation
│   ├── auth-flow.md           # Authentication flows
│   └── error-handling.md      # Error responses
├── examples/
│   ├── index.md               # Examples overview
│   ├── testing-auth.md        # Authentication testing
│   ├── custom-providers.md    # Custom auth providers
│   └── advanced-patterns.md   # Advanced use cases
├── deployment/
│   ├── index.md               # Deployment overview
│   ├── profiles.md            # Configuration profiles
│   └── production.md          # Production setup
└── reference/
    ├── index.md               # Reference overview
    ├── modules.md             # Module documentation
    ├── logging.md             # Logging guide
    └── troubleshooting.md     # Common issues
```

## 🎨 Customization

### Theme Configuration

The documentation uses Material for MkDocs with custom colors and features:

- **Primary Color**: Green (Spring theme)
- **Accent Color**: Teal
- **Dark/Light Mode**: Auto-switching based on system preference
- **Features**: Navigation tabs, search, code copying, syntax highlighting

### Adding Content

1. **Create new markdown files** in appropriate directories
2. **Update navigation** in `mkdocs.yml`
3. **Use Material extensions** for enhanced formatting
4. **Include diagrams** with Mermaid syntax

### Markdown Extensions

Available extensions include:

- **Code highlighting** with syntax highlighting
- **Admonitions** for notes, warnings, tips
- **Mermaid diagrams** for flowcharts and sequences
- **Tabbed content** for organized information
- **Task lists** with checkboxes
- **Mathematical expressions** with MathJax

## 🚀 Deployment Options

### GitHub Pages

1. **Create `.github/workflows/docs.yml`**:

```yaml
name: Deploy Documentation
on:
  push:
    branches: [ main ]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-python@v4
      with:
        python-version: 3.x
    - run: pip install -r requirements.txt
    - run: python -m mkdocs gh-deploy --force
```

2. **Enable GitHub Pages** in repository settings
3. **Set source** to `gh-pages` branch

### Netlify

1. **Connect repository** to Netlify
2. **Set build command**: `mkdocs build`
3. **Set publish directory**: `site/`
4. **Deploy automatically** on push

### Custom Server

```bash
# Build static site
python -m mkdocs build

# Upload site/ directory to web server
rsync -avz site/ user@server:/var/www/html/
```

## 📝 Writing Guidelines

### Style Guide

- **Use clear headings** with proper hierarchy
- **Include code examples** for technical concepts
- **Add diagrams** for complex flows
- **Cross-reference** related sections
- **Keep paragraphs short** for readability

### Documentation Standards

- **Start with overview** in each section
- **Provide working examples** when possible
- **Include troubleshooting tips**
- **Link to relevant code** in the repository
- **Use consistent terminology**

## 🔧 Development

### Live Reloading

The development server automatically reloads when files change:

```bash
python -m mkdocs serve --dev-addr=0.0.0.0:8000
```

### Validation

Check for broken links and validate structure:

```bash
python -m mkdocs build --strict
```

## 💡 Tips

- **Use emoji sparingly** but consistently for visual cues
- **Include diagrams** for complex authentication flows
- **Provide complete examples** with expected outputs
- **Cross-link sections** to improve navigation
- **Keep content up-to-date** with code changes

## 🤝 Contributing

To contribute to the documentation:

1. **Fork the repository**
2. **Create feature branch**
3. **Add/edit documentation**
4. **Test locally** with `python -m mkdocs serve`
5. **Submit pull request**

---

**Happy Documenting!** 📚