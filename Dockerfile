# Use a Node Alpine image (or your choice)
FROM node:18-alpine

# Create work directory
WORKDIR /app

# Copy package.json + package-lock.json
COPY package*.json ./

# If you need dev tools for building sqlite3 from source, do:
# RUN apk add --no-cache python3 make g++

# Install dependencies (production or dev, depending on your needs)
RUN npm install

# Copy the rest of your app
COPY . .

# Expose the port if needed
EXPOSE 3000

# Run your server
CMD ["node", "server.js"]
