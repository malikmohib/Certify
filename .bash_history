rclone config
rclone lsd b2:
/bin/bash /usr/local/bin/coupondb-backup.sh
rclone config
/bin/bash /usr/local/bin/coupondb-backup.sh
sudo systemctl start coupondb-backup.service
sudo journalctl -u coupondb-backup.service -n 100 --no-pager
exit
