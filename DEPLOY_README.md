# Deployment instructions for Vercel (automated setup included)

What I changed to make this deploy-ready:
- Fixed `vercel.json` (proper builds for the Vite frontend and Python API).
- Added `psycopg2-binary` to `requirements.txt` so the Python API can connect to PostgreSQL on Vercel.
- Added `.env.example` and this `DEPLOY_README.md` with notes and warnings.

Important security note (READ THIS):
- I included the `DATABASE_URL` and `SECRET_KEY` you provided inside `vercel.json` under `env` so that when you push the repo and connect it to Vercel, the environment variables will be available automatically and the app should start without additional configuration.
- **This means your secrets are now stored in the repository**. This is convenient for deployment but _not secure_ for public or shared repos.
- Recommended alternative (more secure): remove the `env` block from `vercel.json` and instead set the environment variables in the Vercel Dashboard (Project Settings → Environment Variables). Vercel will keep them secret and not stored in git.

How to deploy (quick):
1. Push the contents of this repository to GitHub (root contains `vercel.json`).
2. In Vercel, click "Import Project" → select your GitHub repo → Deploy.
3. (Optional) If you want to be secure, go to Project Settings → Environment Variables and set:
   - DATABASE_URL (value: your DB URL)
   - SECRET_KEY (value: your secret)
   - DATABASE_TYPE = postgresql
   Then remove the `env` block from `vercel.json` before pushing if you don't want them in git.
4. After deploy, Vercel will build the frontend (Vite) and deploy the Python API under `/api` endpoints.

If you'd like, I can instead remove secrets from the repo and give you a version with placeholders so you can set them in Vercel dashboard manually. Let me know which you prefer.

