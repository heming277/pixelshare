# Use the official Rust image as a parent image
FROM rust:latest

# Set the working directory in the container
WORKDIR /usr/src/pixelshare

# Copy the current directory contents into the container at /usr/src/pixelshare
COPY . .

# Build for release
RUN cargo build --release

# Expose the port the server listens on
EXPOSE 3030

# Run the binary
CMD ["./target/release/pixelshare"]