# Docker

`Dockerfile` here builds from the repository root. The backend image also lives
at `backend/Dockerfile` (build context: `backend/`).

```bash
docker build -f docker/Dockerfile -t appprobe:m1 .
docker run --rm -p 8000:8000 -v "$PWD/workspace:/data/workspace" appprobe:m1
```
