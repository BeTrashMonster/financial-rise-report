import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  DialogProps,
  IconButton,
  Typography,
  Divider,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';

export interface ModalProps extends Omit<DialogProps, 'title'> {
  title?: string;
  onClose: () => void;
  actions?: React.ReactNode;
  children: React.ReactNode;
  showCloseButton?: boolean;
  divider?: boolean;
}

/**
 * Custom Modal Component
 * Accessible dialog wrapper with consistent styling
 */
export const Modal: React.FC<ModalProps> = ({
  title,
  onClose,
  actions,
  children,
  showCloseButton = true,
  divider = true,
  maxWidth = 'sm',
  fullWidth = true,
  ...props
}) => {
  return (
    <Dialog
      {...props}
      onClose={onClose}
      maxWidth={maxWidth}
      fullWidth={fullWidth}
      aria-labelledby={title ? 'modal-title' : undefined}
      aria-describedby="modal-description"
    >
      {title && (
        <>
          <DialogTitle
            id="modal-title"
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              paddingRight: showCloseButton ? 1 : 3,
            }}
          >
            <Typography variant="h6" component="h2">
              {title}
            </Typography>
            {showCloseButton && (
              <IconButton
                aria-label="Close dialog"
                onClick={onClose}
                edge="end"
                sx={{
                  color: (theme) => theme.palette.grey[500],
                }}
              >
                <CloseIcon />
              </IconButton>
            )}
          </DialogTitle>
          {divider && <Divider />}
        </>
      )}

      <DialogContent
        id="modal-description"
        sx={{
          paddingTop: title ? 3 : 2,
        }}
      >
        {children}
      </DialogContent>

      {actions && (
        <>
          {divider && <Divider />}
          <DialogActions
            sx={{
              padding: 2,
              gap: 1,
            }}
          >
            {actions}
          </DialogActions>
        </>
      )}
    </Dialog>
  );
};

export default Modal;
