FROM denoland/deno:2.1.4
WORKDIR /app
COPY . .
RUN deno cache server.ts
USER deno
EXPOSE 8000
CMD ["deno", "run", "--allow-net", "--allow-env", "server.ts"]
