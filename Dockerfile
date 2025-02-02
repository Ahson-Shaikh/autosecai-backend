# Use a lightweight Node image
FROM node:16-alpine

# Create app directory inside the container
WORKDIR /app

# Copy only package.json and package-lock.json first
# (Leverage Docker layer caching)
COPY package*.json ./

# Install production dependencies
RUN npm install --production

# Copy the rest of the application files
COPY . .

# Set environment variables (optional)
ENV PORT=3000

# Expose the port (for documentation only)
EXPOSE 3000

# Start the server
CMD ["node", "server.js"]
