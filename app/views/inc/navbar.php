    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-3">
        <div class="container">
            <a class="navbar-brand" href="/"><?php echo SITENAME; ?></a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample01" aria-controls="navbarsExample01" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarsExample01">
                <ul class="navbar-nav ml-auto">  
                <?php if (isset($_SESSION['user_id'])) : ?>
                    <!-- <li class="nav-item">
                        <a class="nav-link active" href="/users/list">List of users</a>
                    </li> -->
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdownMenuLink" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false"><i class="fas fa-user-circle fa-lg"></i> <?= Session::get('user_fname'); ?></a>
                        <div class="dropdown-menu" aria-labelledby="navbarDropdownMenuLink">
                            <a class="dropdown-item" href="/users/logout">Logout</a>
                        </div>
                    </li>    
                <?php else: ?>
                    <li class="nav-item">
                        <a class="nav-link" href="/users/login">Login</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/users/register">Register</a>
                    </li>
                <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>