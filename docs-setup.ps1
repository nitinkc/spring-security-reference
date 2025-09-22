# PowerShell script to manage MkDocs documentation
# Usage: .\docs-setup.ps1 [command]
# Commands: install, serve, build, deploy

param(
    [string]$Command = "serve"
)

Write-Host "🚀 Spring Security Reference Documentation Manager" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green

switch ($Command.ToLower()) {
    "install" {
        Write-Host "📦 Installing MkDocs and dependencies..." -ForegroundColor Yellow
        
        # Check if Python is installed
        try {
            $pythonVersion = python --version 2>$null
            Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ Python not found. Please install Python 3.7+ first." -ForegroundColor Red
            Write-Host "Download from: https://www.python.org/downloads/" -ForegroundColor Blue
            exit 1
        }
        
        # Check if pip is available
        try {
            pip --version 2>$null | Out-Null
            Write-Host "✅ pip is available" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ pip not found. Please ensure pip is installed." -ForegroundColor Red
            exit 1
        }
        
        # Install requirements
        Write-Host "📦 Installing MkDocs requirements..." -ForegroundColor Yellow
        pip install -r requirements.txt
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Installation completed successfully!" -ForegroundColor Green
            Write-Host "🎉 Run '.\docs-setup.ps1 serve' to start the documentation server" -ForegroundColor Cyan
        }
        else {
            Write-Host "❌ Installation failed. Please check the error messages above." -ForegroundColor Red
        }
    }
    
    "serve" {
        Write-Host "🌐 Starting MkDocs development server..." -ForegroundColor Yellow
        Write-Host "📖 Documentation will be available at: http://localhost:8000" -ForegroundColor Cyan
        Write-Host "🔄 Server will auto-reload when files change" -ForegroundColor Blue
        Write-Host "⏹️ Press Ctrl+C to stop the server" -ForegroundColor Gray
        Write-Host ""
        
        try {
            python -m mkdocs serve --dev-addr=127.0.0.1:8000
        }
        catch {
            Write-Host "❌ Failed to start server. Make sure MkDocs is installed:" -ForegroundColor Red
            Write-Host "   .\docs-setup.ps1 install" -ForegroundColor Yellow
        }
    }
    
    "build" {
        Write-Host "🏗️ Building static documentation site..." -ForegroundColor Yellow
        
        try {
            python -m mkdocs build --clean
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ Documentation built successfully!" -ForegroundColor Green
                Write-Host "📁 Static files are in the 'site' directory" -ForegroundColor Cyan
                Write-Host "🌐 You can serve these files with any web server" -ForegroundColor Blue
            }
        }
        catch {
            Write-Host "❌ Build failed. Make sure MkDocs is installed:" -ForegroundColor Red
            Write-Host "   .\docs-setup.ps1 install" -ForegroundColor Yellow
        }
    }
    
    "deploy" {
        Write-Host "🚀 Deploying to GitHub Pages..." -ForegroundColor Yellow
        
        # Check if we're in a git repository
        if (-not (Test-Path ".git")) {
            Write-Host "❌ Not in a git repository. Please initialize git first." -ForegroundColor Red
            exit 1
        }
        
        try {
            python -m mkdocs gh-deploy --force
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ Documentation deployed successfully!" -ForegroundColor Green
                Write-Host "🌐 Your documentation should be available at your GitHub Pages URL" -ForegroundColor Cyan
            }
        }
        catch {
            Write-Host "❌ Deployment failed. Check the error messages above." -ForegroundColor Red
        }
    }
    
    "check" {
        Write-Host "🔍 Checking documentation for issues..." -ForegroundColor Yellow
        
        try {
            python -m mkdocs build --strict
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ Documentation check passed!" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "❌ Documentation check failed. Fix the issues above." -ForegroundColor Red
        }
    }
    
    default {
        Write-Host "❓ Unknown command: $Command" -ForegroundColor Red
        Write-Host ""
        Write-Host "Available commands:" -ForegroundColor Yellow
        Write-Host "  install  - Install MkDocs and dependencies" -ForegroundColor White
        Write-Host "  serve    - Start development server (default)" -ForegroundColor White
        Write-Host "  build    - Build static site" -ForegroundColor White
        Write-Host "  deploy   - Deploy to GitHub Pages" -ForegroundColor White
        Write-Host "  check    - Check for documentation issues" -ForegroundColor White
        Write-Host ""
        Write-Host "Examples:" -ForegroundColor Cyan
        Write-Host "  .\docs-setup.ps1 install" -ForegroundColor Gray
        Write-Host "  .\docs-setup.ps1 serve" -ForegroundColor Gray
        Write-Host "  .\docs-setup.ps1 build" -ForegroundColor Gray
    }
}