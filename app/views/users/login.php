<?php require APPROOT . '/views/inc/header.php'; ?>
    <div class="container">
        <div class="row">
            <div class="col-md-6 mx-auto">
                <div class="card card-body bg-light mt-5">
                    <?php Session::flash('register_success') ?>
                    <?php Session::flash('login_fail') ?>
                    <h2>Login</h2>
                    <p>Please fill in your credentials</p>
                    <form action="<?php echo URLROOT; ?>/users/login" method="post">
                        <div class="form-group">
                            <label for="email">Email: *</label>
                            <input type="email" name="email" class="form-control <?php echo (!empty($data['email_error'])) ? 'is-invalid' : '' ?>" value="<?php echo $data['email']; ?>">
                            <span class="invalid-feedback"><?php echo $data['email_error'] ?></span>
                        </div>
                        <div class="form-group">
                            <label for="password">Password: *</label>
                            <input type="password" name="password" class="form-control <?php echo (!empty($data['password_error'])) ? 'is-invalid' : '' ?>" value="<?php echo $data['password']; ?>">
                            <span class="invalid-feedback"><?php echo $data['password_error'] ?></span>
                        </div>
                        <div class="form-group">
                            <input type="hidden" name="token" class="form-control" value="<?php echo Token::generate()?>">
                        </div>
                        
                        <div class="row">
                            <div class="col">
                                <input type="submit" value="Login" class="form-control btn btn-success btn-block">
                            </div>
                            <div class="col">
                                <a href="<?php echo URLROOT;?>/users/register" class="btn btn-light btn-block">No an account? Register</a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
<?php require APPROOT . '/views/inc/footer.php'; ?> 