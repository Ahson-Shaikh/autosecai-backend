# AutoSecAI Backend

The backend API server for AutoSecAI, an AI-powered security scanning tool that leverages large language models to detect vulnerabilities in your codebase.

## Features

- **AI Integration**: Connect to OpenAI and Ollama services for code analysis
- **GitHub API**: Clone and analyze repositories via GitHub integration
- **WebSocket Support**: Real-time scanning updates to the frontend
- **Secure Storage**: Encrypted storage of API keys and sensitive information
- **Authentication**: User authentication and authorization system
- **Database**: SQLite database for storing scan results and user information

## Quick Start Guide

### Prerequisites

- Node.js (v14 or later)
- npm or yarn
- Git
- SQLite3

### Setup

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/autosecai-backend.git
cd autosecai-backend
```

2. **Install dependencies**

```bash
npm install
```

3. **Set up environment variables**

Create a `.env` file in the project root:

```
PORT=3001
JWT_SECRET=your_jwt_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
SETTINGS_ENCRYPTION_KEY=your_encryption_key
```

4. **Initialize the database**

```bash
npm run init-db
```

5. **Start the server**

```bash
npm start
```

The backend API will be available at http://localhost:3000

## API Documentation

### Authentication Endpoints

- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `GET /auth/github` - Initiate GitHub OAuth flow
- `GET /auth/github/callback` - GitHub OAuth callback

### Scan Endpoints

- `POST /scan/begin` - Start a new security scan
- `GET /scan/:id` - Get scan details
- `GET /scan/:id/vulnerabilities` - Get vulnerabilities for a scan
- `POST /scan/:id/cancel` - Cancel an ongoing scan

### Settings Endpoints

- `GET /settings/user/api-keys` - Get user API keys (obfuscated)
- `POST /settings/user/api-keys` - Save user API keys
- `POST /settings/user/test-connection` - Test AI connection

## AI Integration

The backend supports two AI services for code analysis:

1. **OpenAI**: Uses the GPT models via OpenAI's API
2. **Ollama**: Uses open-source models via the Ollama API

Configuration for these services is managed through the frontend settings interface and stored securely in the database.

## WebSocket Events

The backend emits the following events during scans:

- `scan-log` - General scan progress updates
- `file-progress` - Updates on the current file being analyzed
- `vulnerability-found` - Notification when a vulnerability is detected

## Deployment

For production deployment:

1. Set up environment variables for production
2. Build the application:
   ```bash
   npm run build
   ```
3. Start the production server:
   ```bash
   npm run start:prod
   ```

## Troubleshooting

### Common Issues

- **Database Errors**: Ensure SQLite is properly installed and the database file has write permissions
- **GitHub API Limits**: Check your GitHub API rate limits if scans are failing
- **AI Connection Issues**: Verify API keys and endpoints in the settings
- **"Invalid URL"**: Make sure Ollama URLs include the protocol (http:// or https://)

## Development

```bash
# Run in development mode with auto-reload
npm run start
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 