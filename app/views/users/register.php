<?php require APPROOT . '/views/inc/header.php'; ?>
    <div class="container">
        <div class="row">
            <div class="col-md-6 mx-auto">
                <div class="card card-body bg-light mt-5">
                    <h2>Create an account</h2>
                    <p>Please fill out this form to register with us</p>
                    <form action="<?php echo URLROOT; ?>/users/register" method="post">
                        <div class="form-group">
                            <label for="firstName">Name: *</label>
                            <input type="text" name="name" class="form-control <?php echo (!empty($data['name_error'])) ? 'is-invalid' : '' ?>" value="<?php echo $data['name']; ?>">
                            <span class="invalid-feedback"><?php echo $data['name_error'] ?></span>
                        </div>
                        <div class="form-group">
                            <label for="email">Email: *</label>
                            <input type="email" name="email" class="form-control <?php echo (!empty($data['email_error'])) ? 'is-invalid' : '' ?>" value="<?php echo $data['email']; ?>">
                            <span class="invalid-feedback"><?php echo $data['email_error'] ?></span>
                        </div>
                        <div class="row">
                            <div class="col">
                                <div class="form-group">
                                    <label for="password">Password: *</label>
                                    <input type="password" name="password" class="form-control <?php echo (!empty($data['password_error'])) ? 'is-invalid' : '' ?>" value="<?php echo $data['password']; ?>">
                                    <span class="invalid-feedback"><?php echo $data['password_error'] ?></span>
                                </div>
                            </div>
                            <div class="col">
                                <label for="confirmPassword">Confirm Password: *</label>
                                <div class="form-group">
                                    <input type="password" name="confirmPassword"  class="form-control <?php echo (!empty($data['confirmPassword_error'])) ? 'is-invalid' : '' ?>" value="<?php echo $data['confirmPassword']; ?>">
                                    <span class="invalid-feedback"><?php echo $data['confirmPassword_error'] ?></span>
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <input type="hidden" name="token" class="form-control" value="<?php echo Token::generate()?>">
                        </div>
                        <div class="row">
                            <div class="col">
                                <input type="submit" value="Register" class="form-control btn btn-success btn-block">
                            </div>
                            <div class="col">
                                <a href="<?php echo URLROOT;?>/users/login" class="btn btn-light btn-block">Have an account? Login</a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
<?php require APPROOT . '/views/inc/footer.php'; ?> 