<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Heresce Shorturl System</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap">
    <style>
        :root {
            --primary: #4361ee;
            --primary-dark: #3a56d4;
            --secondary: #3f37c9;
            --dark: #1a1a2e;
            --light: #f8f9fa;
            --gradient: linear-gradient(135deg, var(--primary), var(--secondary));
            --glass: rgba(255, 255, 255, 0.1);
            --glass-border: rgba(255, 255, 255, 0.2);
            --shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            --transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--dark);
            color: var(--light);
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 25% 25%, rgba(67, 97, 238, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 75% 75%, rgba(63, 55, 201, 0.15) 0%, transparent 50%);
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 2rem;
            overflow-x: hidden;
        }

        .container {
            max-width: 1200px;
            width: 100%;
            text-align: center;
            position: relative;
            z-index: 1;
        }

        h1 {
            font-size: 4rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            background: linear-gradient(90deg, #fff, #aaa);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            line-height: 1.2;
        }

        p {
            font-size: 1.25rem;
            max-width: 600px;
            margin: 0 auto 3rem;
            opacity: 0.9;
            line-height: 1.6;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 1rem 2.5rem;
            background: var(--gradient);
            color: white;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 600;
            font-size: 1.1rem;
            box-shadow: var(--shadow);
            border: none;
            cursor: pointer;
            transition: var(--transition);
            position: relative;
            overflow: hidden;
            z-index: 1;
        }

        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, var(--primary-dark), var(--secondary));
            z-index: -1;
            transition: var(--transition);
            opacity: 0;
        }

        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.3);
        }

        .btn:hover::before {
            opacity: 1;
        }

        .admin-login {
            margin-top: 4rem;
        }

        .floating-shapes {
            position: absolute;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            pointer-events: none;
            z-index: -1;
        }

        .shape {
            position: absolute;
            border-radius: 50%;
            filter: blur(60px);
            opacity: 0.2;
        }

        .shape-1 {
            width: 300px;
            height: 300px;
            background: var(--primary);
            top: 20%;
            left: 10%;
            animation: float 8s ease-in-out infinite;
        }

        .shape-2 {
            width: 400px;
            height: 400px;
            background: var(--secondary);
            bottom: 10%;
            right: 10%;
            animation: float 10s ease-in-out infinite reverse;
        }

        @keyframes float {
            0%, 100% {
                transform: translateY(0) rotate(0deg);
            }
            50% {
                transform: translateY(-20px) rotate(5deg);
            }
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 2.5rem;
            }
            
            p {
                font-size: 1rem;
                margin-bottom: 2rem;
            }
            
            .btn {
                padding: 0.8rem 1.8rem;
                font-size: 1rem;
            }
        }

        /* Modern glass effect */
        .glass-card {
            background: var(--glass);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 20px;
            border: 1px solid var(--glass-border);
            padding: 3rem;
            max-width: 800px;
            margin: 0 auto;
            box-shadow: var(--shadow);
        }
    </style>
</head>
<body>
    <div class="floating-shapes">
        <div class="shape shape-1"></div>
        <div class="shape shape-2"></div>
    </div>

    <div class="container">
        <div class="glass-card">
            <h1>Heresce Shorturl System</h1>
            <p>Advanced URL rotation system with intelligent routing, security features, and real-time analytics</p>
            
            <div class="admin-login">
                <a href="/admin/" class="btn">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 8px;">
                        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"></path>
                    </svg>
                    Admin Panel
                </a>
            </div>
        </div>
    </div>

    <script>
        // Add subtle interactive effects
        document.addEventListener('mousemove', (e) => {
            const container = document.querySelector('.container');
            const xAxis = (window.innerWidth / 2 - e.pageX) / 25;
            const yAxis = (window.innerHeight / 2 - e.pageY) / 25;
            container.style.transform = `rotateY(${xAxis}deg) rotateX(${yAxis}deg)`;
        });

        // Reset rotation when mouse leaves
        document.querySelector('body').addEventListener('mouseleave', () => {
            document.querySelector('.container').style.transform = 'rotateY(0deg) rotateX(0deg)';
        });
    </script>
</body>
</html>
