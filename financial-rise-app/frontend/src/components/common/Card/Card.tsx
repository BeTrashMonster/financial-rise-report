import React from 'react';
import {
  Card as MuiCard,
  CardProps as MuiCardProps,
  CardContent,
  CardHeader,
  CardActions,
  Divider,
} from '@mui/material';

export interface CardProps extends MuiCardProps {
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
  headerAction?: React.ReactNode;
  children: React.ReactNode;
  noPadding?: boolean;
  divider?: boolean;
}

/**
 * Custom Card Component
 * Provides consistent card styling throughout the application
 */
export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  actions,
  headerAction,
  children,
  noPadding = false,
  divider = false,
  ...props
}) => {
  return (
    <MuiCard {...props}>
      {(title || subtitle) && (
        <>
          <CardHeader
            title={title}
            subheader={subtitle}
            action={headerAction}
            titleTypographyProps={{
              variant: 'h6',
              component: 'h2',
            }}
            subheaderTypographyProps={{
              variant: 'body2',
            }}
          />
          {divider && <Divider />}
        </>
      )}

      <CardContent
        sx={{
          padding: noPadding ? 0 : undefined,
          '&:last-child': {
            paddingBottom: noPadding ? 0 : undefined,
          },
        }}
      >
        {children}
      </CardContent>

      {actions && (
        <>
          {divider && <Divider />}
          <CardActions
            sx={{
              padding: 2,
              justifyContent: 'flex-end',
            }}
          >
            {actions}
          </CardActions>
        </>
      )}
    </MuiCard>
  );
};

export default Card;
