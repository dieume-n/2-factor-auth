<?php require APPROOT . '/views/inc/header.php'; ?>
    <div class="container">
        <div class="row">
            <div class="col-md-6 mx-auto">
                <div class="card card-body bg-light mt-5">
                    <h2>Timebase Authentication</h2>
                    <hr>
                    <form action="<?php echo URLROOT; ?>/users/auth" method="post">
                        <div class="row">
                            <div class="col-md-6 mx-auto">
                                <img src="<?php echo $data['qrcode'] ?>" alt="">
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mx-auto mt-3">
                                <div class="form-group">
                                    <input type="password" name="secret" class="form-control <?php echo (!empty($data['secret_error'])) ? 'is-invalid' : '' ?>" value="<?php echo $data['secret']; ?>">
                                    <span class="invalid-feedback"><?php echo $data['secret_error'] ?></span>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mx-auto">
                                <input type="submit" value="Authenticate" class="form-control btn btn-success btn-block">
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
<?php require APPROOT . '/views/inc/footer.php'; ?> 