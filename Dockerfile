FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev || npm install --force
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
