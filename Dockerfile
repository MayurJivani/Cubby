# For hosts that want a container instead of the systemd unit in deploy/.
# No dependencies and no build step, so this is just node plus the source.
FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY bin ./bin
ENV PORT=4747 CUBBY_DIR=/data CUBBY_TRUST_PROXY=1
# The volume inherits this ownership when Docker creates it, so the unprivileged
# user can actually write to it.
RUN mkdir -p /data && chown node:node /data
VOLUME /data
EXPOSE 4747
USER node
CMD ["node", "bin/cubby.js"]
