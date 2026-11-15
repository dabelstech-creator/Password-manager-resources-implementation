FROM swift:6.0-jammy AS build
WORKDIR /app

COPY Package.swift ./
COPY Sources ./Sources
RUN swift build -c release --product Run

FROM swift:6.0-jammy
WORKDIR /app
COPY --from=build /app/.build/release/Run ./Run

ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["./Run"]
