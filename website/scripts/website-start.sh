# Set the subdirectory name for the dev-portal app
PREVIEW_DIR=website-preview
# The product for which we are running local preview mode
PRODUCT=boundary

should_pull=true

# Clone the dev-portal project, if needed
if [ ! -d "$PREVIEW_DIR" ]; then
    echo "⏳ Cloning the dev-portal repo, this might take a while..."
    git clone --depth=1 https://github.com/hashicorp/dev-portal.git "$PREVIEW_DIR"
    should_pull=false
fi


cd "$PREVIEW_DIR"

# If the directory already existed, pull to ensure the dev-portal clone is fresh
if [ "$should_pull" = true ] && [ -d ".git" ]; then
    git fetch origin main
    git reset --hard origin/main
fi

# Run the dev-portal content-repo start script
REPO=$PRODUCT PREVIEW_DIR="$PREVIEW_DIR" npm run start:local-preview
